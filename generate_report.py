"""
generate_report.py
==================
ISA/IEC 62443-3-3 OT Firewall Compliance PDF report for IACS_Monitor (F-02).

Reads the live database (Findings, Attestations, firewall inventory) and
renders a PDF with reportlab:

  * cover + executive summary (severity x status counts)
  * findings grouped by checklist section and check (SR / checklist refs,
    evidence summary per finding)
  * zone-documentation attestation status (checklist 1.1-1.6)
  * firewall inventory (devices, active / disabled rule counts, NAT rows)
  * permitted communication paths & permissive policies: the lines selected
    in Access Review (docs/access-path-review.md), grouped by classification
  * coverage: every implemented check (derived from
    app.models.CHECK_TYPE_REFERENCE, so the table is always complete) with
    its finding count; checks with zero findings are labelled "no data"
    when the inputs that check needs are absent from the database, else
    "no findings"
  * full ISA/IEC 62443 control mapping table

CLI::

    python generate_report.py [--db URL] [--out FILE.pdf] [--baseline NAME]
                              [--include-closed] [--site "Name"]

``--db`` defaults to $IACS_DATABASE_URL, then to sqlite:///./iasc_monitor.db.
The database is only ever read: SQLite files are opened read-only
(``mode=ro``) and a missing SQLite file is an error rather than being
created.  The API serves the same report at GET /reports/compliance.pdf.

Every string that comes from the database is escaped before it is handed to
reportlab's Paragraph (which parses a small XML markup language) and long
values are truncated so a single table cell can never exceed a page.
"""
from __future__ import annotations

import argparse
import io
import json
import logging
import os
import re
import sys
import threading
from collections import Counter, defaultdict
from datetime import datetime, timedelta, timezone
from pathlib import Path
from typing import Any, Iterable, Optional
from xml.sax.saxutils import escape as _xml_escape

from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle, getSampleStyleSheet
from reportlab.lib.units import cm, mm
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.platypus import (
    Preformatted,
    BaseDocTemplate,
    Frame,
    HRFlowable,
    NextPageTemplate,
    PageBreak,
    PageTemplate,
    Paragraph,
    Spacer,
    Table,
    TableStyle,
)
from reportlab.platypus.flowables import KeepTogether
from reportlab.platypus.tableofcontents import TableOfContents

ROOT = Path(__file__).resolve().parent
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from app.purdue import fmt_level  # noqa: E402  (pure module, no DB binding)

log = logging.getLogger("iasc.report")

DEFAULT_OUT = "isa62443_compliance_report.pdf"
MAX_FINDINGS_PER_CHECK = 50       # rows printed per check (count is always exact)
ATTESTATION_STALE_DAYS = 365      # matches alert_engine.review_zone_documentation
SEVERITIES = ["critical", "high", "medium", "low", "info"]
STATUSES = ["open", "acknowledged", "closed"]
FALSE_POSITIVE = "false_positive"     # SF: its own section, never "in scope"
ATTESTABLE_ROWS = {
    "1.1": "OT zones are formally defined and documented",
    "1.2": "Zones are defined by risk / consequence",
    "1.3": "Zone boundaries are enforced by controls (FW/VLAN)",
    "1.4": "Communication conduits between zones are documented",
    "1.5": "Security requirements are defined per zone",
    "1.6": "Zone documentation has been reviewed and approved",
}
# Checklist sections of the OT Firewall Review 62443 workbook.
SECTION_NAMES = {
    "1": "Zone Documentation",
    "2": "Zone & Conduit Architecture",
    "3": "Firewall Rule Base",
    "4": "Remote Access",
    "5": "Management Access",
    "6": "Logging & Monitoring",
    "7": "Resilience & Asset Inventory",
    "8": "Traffic Analysis",
    "9": "Infrastructure Services & Hardening",
    # owner 2026-10-12: checks with no workbook row (judged by their 62443-3-3 SR)
    "?": "Other",
}

# Checks that construct Findings with inline SR metadata instead of reading
# CHECK_TYPE_REFERENCE (same list as GET /findings/category-reference).
SUPPLEMENTAL_CHECKS = {
    "cross_fw_no_rules":               ("SR 5.1",         "5.1", "high",     "config_review"),
    "cross_fw_missing_deny_all":       ("SR 5.1 RE1",     "5.1", "high",     "config_review"),
    "cross_fw_any_any_permit":         ("SR 5.1 RE1",     "5.1", "critical", "config_review"),
    "cross_fw_asymmetric_permit":      ("SR 5.2",         "5.2", "medium",   "config_review"),
    "cross_fw_same_permit_both_sides": ("SR 5.2",         "5.2", "info",     "config_review"),
    "unauthorized_industrial_write":   ("SR 2.1, SR 3.5", "8.4", "critical", "periodic_review"),
}

# ---------------------------------------------------------------------------
# Colour palette
# ---------------------------------------------------------------------------
NAVY = colors.HexColor("#14173a")
NAVY_2 = colors.HexColor("#2d4170")
WHITE = colors.white
TEAL = colors.HexColor("#1b9e94")          # template accent (headings, section numbers)
LIGHT_GREY = colors.HexColor("#f5f5f5")
MID_GREY = colors.HexColor("#cccccc")
DARK_GREY = colors.HexColor("#555555")
TOTAL_BG = colors.HexColor("#e8ecf4")
OK_GREEN = colors.HexColor("#1e8449")

SEV_COLOUR = {
    "critical": colors.HexColor("#b3001b"),
    "high": colors.HexColor("#e03a2f"),
    "medium": colors.HexColor("#e5a53a"),
    "low": colors.HexColor("#3b7dd8"),
    "info": colors.HexColor("#6c757d"),
}
SEV_BG = {
    "critical": colors.HexColor("#fdecea"),
    "high": colors.HexColor("#fef3e8"),
    "medium": colors.HexColor("#fef9e7"),
    "low": colors.HexColor("#eaf4fb"),
    "info": colors.HexColor("#f4f6f7"),
}


# ---------------------------------------------------------------------------
# Text helpers
# ---------------------------------------------------------------------------
_CTRL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


def esc(value: Any, limit: Optional[int] = 400) -> str:
    """Make arbitrary (DB-sourced) text safe for reportlab Paragraph markup:
    stringify, drop control characters, truncate, then XML-escape & < > " '."""
    if value is None:
        return ""
    s = value if isinstance(value, str) else str(value)
    s = _CTRL_RE.sub(" ", s)
    if limit is not None and len(s) > limit:
        s = s[: max(0, limit - 1)] + "…"
    return _xml_escape(s, {'"': "&quot;", "'": "&#39;"})


def fmt_check_name(name: Optional[str]) -> str:
    """snake_case check name -> Title Case display name."""
    m = re.fullmatch(r"zone_doc_(\d+)_(\d+)", name or "")
    if m:
        return f"Zone Documentation {m.group(1)}.{m.group(2)}"
    return (name or "unspecified").replace("_", " ").title()


def fmt_category(cat: Optional[str]) -> str:
    return {"real_time": "Real-Time", "periodic_review": "Periodic Review",
            "config_review": "Config Review", "traffic_review": "Traffic Review"}.get(cat or "", cat or "")


def fmt_dt(value: Any) -> str:
    if not value:
        return ""
    if isinstance(value, datetime):
        if value.tzinfo is None:
            value = value.replace(tzinfo=timezone.utc)
        return value.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    return str(value)


def section_of(checklist_id: Optional[str]) -> str:
    """'2.1, 2.2' -> '2'; None/garbage -> '?'."""
    m = re.match(r"\s*(\d+)", checklist_id or "")
    return m.group(1) if m else "?"


def _checklist_sort_key(checklist_id: Optional[str]):
    first = (checklist_id or "").split(",")[0].strip()
    parts = re.findall(r"\d+", first)
    return tuple(int(p) for p in parts) or (999,)


def evidence_summary(detail: Any, limit: int = 360) -> str:
    """Compact 'key: value; key: value' summary of a Finding.detail dict
    (nested values JSON-encoded).  Plain text - caller escapes."""
    if detail is None or detail == {}:
        return ""
    if isinstance(detail, str):
        try:
            detail = json.loads(detail)
        except ValueError:
            return detail[:limit]
    if not isinstance(detail, dict):
        return str(detail)[:limit]
    parts = []
    for k, v in detail.items():
        if v is None or v == "" or v == [] or v == {} or k == "severity_reason":
            continue
        if isinstance(v, (dict, list)):
            try:
                v = json.dumps(v, default=str, separators=(",", ":"))
            except (TypeError, ValueError):
                v = str(v)
        v = str(v)
        if len(v) > 120:
            v = v[:119] + "…"
        parts.append(f"{k}: {v}")
        if sum(len(p) + 2 for p in parts) > limit:
            break
    s = "; ".join(parts)
    return s if len(s) <= limit else s[: limit - 1] + "…"


# ---------------------------------------------------------------------------
# Check catalogue (always derived from app.models.CHECK_TYPE_REFERENCE)
# ---------------------------------------------------------------------------
def check_catalogue() -> dict[str, dict]:
    """{check_name: {sr, checklist_id, severity, category, source, fr, sl,
    sl_by_sr}} for every implemented structured check.  ``fr`` / ``sl`` come
    from app.security_levels: the FRs of the SRs and the lowest security
    level at which one of them applies (None: no 62443-3-3 SR)."""
    from app.models import CHECK_TYPE_REFERENCE

    cat: dict[str, dict] = {}
    for name, (sr, cl, sev, category) in CHECK_TYPE_REFERENCE.items():
        cat[name] = dict(sr=sr, checklist_id=cl, severity=sev, category=category,
                         source="reference")
    for name, (sr, cl, sev, category) in SUPPLEMENTAL_CHECKS.items():
        cat.setdefault(name, dict(sr=sr, checklist_id=cl, severity=sev, category=category,
                                  source="supplemental"))
    from app.security_levels import describe
    for info in cat.values():
        info.update(describe(info["sr"]))       # fr, sl, sl_by_sr (62443-3-3)
    return cat


# Which data each check needs; used to tell "no data" from "no findings".
# Keys are input names computed in _input_counts().  Checks not listed fall
# back to prefix/category rules in _inputs_for().
_CHECK_INPUTS: dict[str, tuple[str, ...]] = {
    "conduit_matrix_drift": ("sessions", "rules"),
    "unused_policy": ("rules",),
    "disabled_rule": ("rules",),
    "denied_trend": ("faz_events",),
    "cleartext_protocol": ("sessions",),
    "mgmt_protocol": ("sessions",),
    "ot_it_dependency": ("sessions",),
    "cleartext_credentials": ("sessions",),
    "engineering_access_unapproved": ("sessions",),
    "smbv1_legacy": ("sessions",),
    # FO-03: without a baseline the check reports unidentified industrial clients
    "unknown_device": ("hosts",),
    # FO-01: a segment comes from firewall subnets, switch VLANs or a capture
    "flat_control_segment": ("hosts", "segments"),
    "ip_conflict": ("hosts",),
    "misplaced_device": ("hosts",),
    "shadow_rule": ("rules",),
    "historian_in_control_zone": ("host_roles",),
    # batch B / C reviews (audit 2026-10-15): no data -> "no data", not PASS
    "sis_zone_not_isolated": ("hosts",),
    "transient_device_in_ot_zone": ("hosts",),
    "default_credentials_observed": ("sessions",),
    "weak_tls_observed": ("sessions",),
    "mgmt_access_not_restricted": ("host_roles", "sessions"),
    # IO-04: consumer Wi-Fi / router OUIs in captures too
    "wireless_in_ot_zone": ("hosts",),
    "multi_homed_host": ("hosts",),
    "rogue_dhcp_server": ("sessions",),
    "dead_default_gateway": ("sessions",),
    # the one check sourced from the IEC 62443-3-2 zone documentation
    "undocumented_conduit": ("zone_docs",),
    "host_in_multiple_zones": ("zone_docs",),
    "network_in_multiple_zones": ("zone_docs",),
    "policy_spans_multiple_conduits": ("zone_docs", "rules"),
    "blocked_cross_zone_attempts": ("sessions",),
    "conduit_service_blocked": ("zone_docs", "sessions"),
    "mgmt_access_from_wrong_zone": ("sessions",),
    "single_path_critical_device": ("host_roles",),
    "no_path_redundancy_verified": ("host_roles",),
    "undocumented_lldp_device": ("host_roles",),
    "firmware_not_documented": ("host_roles",),
    "ntp_sync": ("sessions",),
    "fqdn_in_policy": ("rules",),
    "vlan_zone_mismatch": ("switch_vlans",),
    "switch_port_no_nac": ("switch_ports",),
    "switch_unused_port_enabled": ("switch_ports",),
    "ghost_vlan": ("switch_vlans",),
    "intervlan_routing_unchecked": ("fw_interfaces",),
    "rule_conduit_drift": ("rules", "baseline"),
    "access_path_permissive": ("rules",),
    "unauthorized_industrial_write": ("protocol_details",),
    "switch_snmp_default_community": ("switch_configs",),
    "switch_snmp_cleartext_community": ("switch_configs",),
    "switch_insecure_mgmt_protocol": ("switch_configs",),
}
#: DR-01: checks that judge a crossing by Purdue level.  Without any level
#: on the site's firewall interfaces / boundaries they cannot produce a
#: finding, so "no findings" would read as a pass - they are "no data".
_LEVEL_CHECKS = frozenset({
    "transient_device_in_ot_zone",     # needs host Purdue levels (L0-L2)
    "chain_it_ot_bypass", "chain_mgmt_wrong_zone", "chain_ot_upward_skip", "dmz_bypass",
    "path_ot_internet_egress", "vpn_direct_to_ot", "config_vpn_direct_to_ot", "dead_end_permit",
    "nat_hides_source_into_ot", "access_path_permissive", "rule_it_ot_bypass",
    "rule_ot_it_dependency", "rule_mgmt_wrong_zone", "rule_cleartext_creds",
    "switch_routes_between_zones", "switch_dual_gateway", "intervlan_routing_unchecked",
    "session_it_ot_bypass", "session_ot_internet_egress", "session_mgmt_from_non_admin",
    "session_remote_access_bypass", "ot_it_dependency", "mgmt_access_from_wrong_zone",
    "cleartext_credentials", "it_ot_bypass", "ot_internet_egress", "remote_access_bypass",
    "config_industrial_dpi_missing",
    "config_wireless_in_ot",           # the SSID's landing interface / VLAN must carry a label (audit 2026-10-19)
})
_INPUT_LABELS = {
    "purdue_levels": "Purdue levels on firewall interfaces",
    "faz_events": "FortiAnalyzer / syslog events",
    "sessions": "observed sessions (pcap)",
    "rules": "firewall rules",
    "hosts": "hosts",
    "host_roles": "LLDP/CDP host roles",
    "switch_vlans": "switch VLAN data",
    "switch_ports": "FortiSwitch port data (FortiLink or FortiSwitchOS config)",
    "fw_interfaces": "firewall interfaces",
    "baseline": "an audit baseline",
    "protocol_details": "decoded industrial protocol data",
    "switch_configs": "switch running-configs",
    "segments": "network segments (firewall subnets, switch VLANs or a capture segment)",
    "zone_docs": "IEC 62443-3-2 zones (Zones & Conduits)",
}


def _inputs_for(name: str, info: dict) -> tuple[str, ...]:
    base = _inputs_for_base(name, info)
    if name in _LEVEL_CHECKS and "purdue_levels" not in base:
        return tuple(base) + ("purdue_levels",)
    return base


def _inputs_for_base(name: str, info: dict) -> tuple[str, ...]:
    if name in _CHECK_INPUTS:
        return _CHECK_INPUTS[name]
    if name.startswith("zone_doc_"):
        return ()                       # attestation-backed: always evaluable
    if name.startswith("session_"):
        return ("sessions",)
    if name.startswith("rule_") or name.startswith("cross_fw_"):
        return ("rules",)
    if info.get("category") == "real_time":
        return ("faz_events",)
    return ()


# ---------------------------------------------------------------------------
# Data collection
# ---------------------------------------------------------------------------
def _input_counts(db, baseline_row, site_id: Optional[int] = None) -> dict[str, int]:
    from sqlalchemy import func
    from app.models import (
        FirewallInterface, FirewallRule, FortiAnalyzerEvent, Host,
        NetworkSession, ProtocolDetail, SwitchInterface, SwitchVlan,
    )

    def cnt(q):
        try:
            return int(q.scalar() or 0)
        except Exception:  # pragma: no cover - table missing on an old schema
            db.rollback()
            return 0

    def sf(q, model):
        return q if site_id is None else q.filter(model.site_id == site_id)

    sessions = db.query(func.count(NetworkSession.id))
    fw_ifaces = db.query(func.count(FirewallInterface.id))
    details = db.query(func.count(ProtocolDetail.id))
    if site_id is not None:  # children: scoped through their parent
        from app.models import Firewall
        sessions = sessions.join(Host, Host.id == NetworkSession.src_host_id).filter(Host.site_id == site_id)
        fw_ifaces = fw_ifaces.join(Firewall, Firewall.id == FirewallInterface.firewall_id) \
                             .filter(Firewall.site_id == site_id)
        details = details.join(NetworkSession, NetworkSession.id == ProtocolDetail.session_id) \
                         .join(Host, Host.id == NetworkSession.src_host_id).filter(Host.site_id == site_id)
    return {
        "faz_events": cnt(sf(db.query(func.count(FortiAnalyzerEvent.id)), FortiAnalyzerEvent)),
        "sessions": cnt(sessions),
        "rules": cnt(sf(db.query(func.count(FirewallRule.id)), FirewallRule)),
        "hosts": cnt(sf(db.query(func.count(Host.id)), Host)),
        "host_roles": cnt(sf(db.query(func.count(Host.id)).filter(Host.role.isnot(None)), Host)),
        "switch_vlans": cnt(sf(db.query(func.count(SwitchVlan.id)), SwitchVlan)),
        "switch_ports": cnt(sf(db.query(func.count(SwitchInterface.id))
                               .filter(SwitchInterface.source_file.like("forti%:%")), SwitchInterface)),
        # switches with interfaces read from a running-config (hardening checks)
        "switch_configs": cnt(sf(db.query(func.count(func.distinct(SwitchInterface.device_name)))
                                 .filter(SwitchInterface.mode.isnot(None)), SwitchInterface)),
        "fw_interfaces": cnt(fw_ifaces),
        "protocol_details": cnt(details),
        "baseline": 1 if baseline_row is not None else 0,
        "purdue_levels": _level_count(db, site_id),
        "segments": _segment_sources(db, site_id),
        "zone_docs": _zone_doc_count(db, site_id),
    }


def _zone_doc_count(db, site_id: Optional[int]) -> int:
    from sqlalchemy import func
    try:
        from app.models import IecZone
        q = db.query(func.count(IecZone.id))
        return int((q if site_id is None else q.filter(IecZone.site_id == site_id)).scalar() or 0)
    except Exception:  # pragma: no cover - table missing on an old schema
        db.rollback()
        return 0


def _segment_sources(db, site_id: Optional[int]) -> int:
    """FO-01: sources a segment can come from - firewall interfaces with a
    network, switch VLANs, captures with a segment."""
    from sqlalchemy import func
    from app.models import Firewall, FirewallInterface, PcapCapture, SwitchVlan
    try:
        fw = db.query(func.count(FirewallInterface.id)).join(
            Firewall, Firewall.id == FirewallInterface.firewall_id).filter(
            FirewallInterface.network_cidr.isnot(None))
        vl = db.query(func.count(SwitchVlan.id))
        cap = db.query(func.count(PcapCapture.id)).filter(PcapCapture.segment.isnot(None))
        if site_id is not None:
            fw = fw.filter(Firewall.site_id == site_id)
            vl = vl.filter(SwitchVlan.site_id == site_id)
            cap = cap.filter(PcapCapture.site_id == site_id)
        return int(fw.scalar() or 0) + int(vl.scalar() or 0) + int(cap.scalar() or 0)
    except Exception:  # pragma: no cover - table missing on an old schema
        db.rollback()
        return 0


def _level_count(db, site_id: Optional[int]) -> int:
    """DR-01: firewall interfaces with an operator / derived Purdue level
    (the automatic L5 of a remote-access tunnel does not count - it alone
    cannot place any crossing) plus firewall devices with a boundary."""
    from sqlalchemy import func
    from app.models import Firewall, FirewallDevice, FirewallInterface
    try:
        q = db.query(func.count(FirewallInterface.id)).join(Firewall, Firewall.id == FirewallInterface.firewall_id) \
              .filter(FirewallInterface.purdue_level.isnot(None), FirewallInterface.remote_access.is_(None))
        d = db.query(func.count(FirewallDevice.id)).filter(FirewallDevice.purdue_zone_from.isnot(None),
                                                           FirewallDevice.purdue_zone_to.isnot(None))
        if site_id is not None:
            q = q.filter(Firewall.site_id == site_id)
            d = d.filter(FirewallDevice.site_id == site_id)
        return int(q.scalar() or 0) + int(d.scalar() or 0)
    except Exception:  # pragma: no cover - old schema
        db.rollback()
        return 0


_FINDING_COLS = ("id", "check_name", "title", "severity", "status", "isa62443_sr",
                 "checklist_id", "device_name", "category", "created_at", "detail")
_FP_COLS = _FINDING_COLS + ("false_positive_reason", "false_positive_by", "false_positive_at")
_CLOSED_COLS = _FINDING_COLS + ("closed_at", "acknowledged_by", "notes", "last_seen")
_MAX_CLOSED = 300        # closed findings listed in their own section (owner 2026-10-14)
_ATT_COLS = ("id", "checklist_id", "attested_by", "attested_at", "notes",
             "proof_filename", "baseline_id", "is_current")
_DEV_COLS = ("id", "name", "vendor", "device_hostname", "firmware_version",
             "purdue_zone_from", "purdue_zone_to")


def _report_details(db, site_id: Optional[int]) -> dict:
    """The site's report details (Reports page); defaults when nothing is stored."""
    d = {"client_name": None, "project_name": None, "author": None, "author_email": None, "version": "1.0",
         "classification": "Confidential Security Data (CSD)", "distribution": [], "revisions": [], "constraints": None}
    if site_id is None:
        return d
    from app.models import ReportDetails
    row = db.query(ReportDetails).filter(ReportDetails.site_id == site_id).one_or_none()
    if row is None:
        return d
    for k in ("client_name", "project_name", "author", "author_email", "version", "classification", "constraints"):
        v = getattr(row, k)
        if v not in (None, ""):
            d[k] = v
    d["distribution"] = list(row.distribution or [])
    d["revisions"] = list(row.revisions or [])
    return d


def _scope_networks(db, site_id: Optional[int]) -> list:
    """The networks in scope: firewall / switch interface networks with their level, then declared subnets."""
    from app.models import Firewall, FirewallInterface, SubnetZone
    out, seen = [], set()
    q = db.query(FirewallInterface).join(Firewall, Firewall.id == FirewallInterface.firewall_id)
    if site_id is not None:
        q = q.filter(Firewall.site_id == site_id)
    for i in q.order_by(FirewallInterface.id):
        n = i.network_cidr
        if not n or n in seen or str(i.role or "").lower() == "wan":
            continue
        seen.add(n)
        lvl = i.purdue_level
        out.append(f"{n}" + (f" (L{lvl:g})" if isinstance(lvl, (int, float)) else "") + (f" {i.alias}" if i.alias else ""))
    zq = db.query(SubnetZone)
    if site_id is not None:
        zq = zq.filter(SubnetZone.site_id == site_id)
    for z in zq:
        if z.cidr and z.cidr not in seen:
            seen.add(z.cidr)
            out.append(f"{z.cidr}" + (f" (L{z.purdue_level:g})" if isinstance(z.purdue_level, (int, float)) else "") + (f" {z.zone_name}" if z.zone_name else ""))
    return out[:60]


def _finding_dict(f) -> dict:
    return {
        "id": f.id, "check_name": f.check_name, "title": f.title,
        "severity": (f.severity or "info").lower(), "status": (f.status or "open").lower(),
        "isa62443_sr": f.isa62443_sr, "checklist_id": f.checklist_id,
        "device_name": f.device_name, "category": f.category,
        "created_at": f.created_at, "detail": f.detail,
        **_sl_of(f.isa62443_sr),
    }


def _sev_rank(sev: Optional[str]) -> int:
    return SEVERITIES.index(sev) if sev in SEVERITIES else len(SEVERITIES)


def _sl_of(sr_text) -> dict:
    from app.security_levels import frs, security_level
    return {"fr": frs(sr_text), "sl": security_level(sr_text)}


def _in_target(sl: Optional[int], target_sl: Optional[int]) -> bool:
    """In scope at target level ``target_sl`` (None = every level).  A check
    or finding with no 62443-3-3 level applies at every target level."""
    return target_sl is None or sl is None or sl <= target_sl


def fmt_sl(sl: Optional[int]) -> str:
    return f"SL{sl}" if sl else "—"


def fmt_fr(fr_list) -> str:
    return ", ".join(fr_list or []) or "—"


def collect_report_data(db, *, baseline: Optional[str] = None,
                        include_closed: bool = False, site: Optional[str] = None,
                        site_id: Optional[int] = None,
                        target_sl: Optional[int] = None,
                        now: Optional[datetime] = None,
                        include_zones: bool = True,
                        apply_check_selection: bool = True) -> dict:
    """Read everything the report needs from ``db`` (a SQLAlchemy Session).

    ``apply_check_selection`` (owner 2026-10-14): leave out the checks the site
    excluded on the Reports page (app/report_checks.py) - their findings leave the
    findings, false positives, severity summary and coverage; ``excluded_checks``
    lists the groups / checks left out.  Site reports only.

    ``include_zones``: add the IEC 62443-3-2 "Zones and Conduits" section
    (only when the site has zones) and judge each device finding against
    the SL-T of its zone.  View-time only: findings, severities and counts
    are the same either way.

    ``target_sl``: ISA/IEC 62443 target security level (1-4).  Findings and
    checks whose 62443-3-3 requirements first apply above it are left out
    (app/security_levels.py); None = every level.

    ``baseline``: name of the baseline whose attestations are reported
    (default: the active baseline).  Raises LookupError if it does not exist.
    ``include_closed``: add the "Closed Findings" section (owner 2026-10-14) - the
    findings in scope (tables, coverage, sections) stay open + acknowledged; closed
    findings are listed separately with their closed date and notes.
    ``site_id``: restrict every section to one site (multi-site); None = all
    sites.  ``site`` is only the label printed on the cover / footer.
    """
    from sqlalchemy import func
    from app.models import (
        Attestation, ApprovedCommsEntry, ApprovedHost, Baseline, Finding,
        FirewallDevice, FirewallRule,
    )
    try:
        from app.models import NatRule
    except ImportError:  # pragma: no cover
        NatRule = None

    now = now or datetime.now(timezone.utc)
    site_code = None
    if site_id is not None:
        from app.models import Site
        site_code = db.query(Site.code).filter(Site.id == site_id).scalar()
        if not site:          # DR-12: the cover names the site unless --site overrides it
            site = db.query(Site.name).filter(Site.id == site_id).scalar()

    def sf(q, model):
        """Filter to the requested site (no-op for an all-sites report)."""
        return q if site_id is None else q.filter(model.site_id == site_id)

    # ---- baseline (names are unique per site since multi-site phase 2)
    if baseline:
        b = sf(db.query(Baseline), Baseline).filter(Baseline.name == baseline) \
              .order_by(Baseline.id.asc()).first()
        if b is None:
            raise LookupError(f"baseline {baseline!r} not found"
                              + (" in this site" if site_id is not None else ""))
    else:
        b = sf(db.query(Baseline), Baseline).filter(Baseline.is_active.is_(True)) \
              .order_by(Baseline.created_at.desc()).first()
    baseline_info = None
    if b is not None:
        baseline_info = {
            "id": b.id, "name": b.name, "is_active": bool(b.is_active),
            "description": b.description, "created_at": b.created_at,
            "comms_entries": db.query(func.count(ApprovedCommsEntry.id))
                               .filter(ApprovedCommsEntry.baseline_id == b.id).scalar() or 0,
            "approved_hosts": db.query(func.count(ApprovedHost.id))
                                .filter(ApprovedHost.baseline_id == b.id).scalar() or 0,
        }

    # ---- checks the site left out of the report (owner 2026-10-14)
    from app import report_checks as _rc
    excluded = _rc.exclusions(db, site_id) if (apply_check_selection and site_id is not None) else {}

    # ---- severity x status counts (all findings, regardless of filter)
    sev_status: dict[str, Counter] = defaultdict(Counter)
    for sev, st, sr_txt, chk, n in sf(db.query(Finding.severity, Finding.status, Finding.isa62443_sr,
                                               Finding.check_name, func.count(Finding.id)), Finding) \
                        .group_by(Finding.severity, Finding.status, Finding.isa62443_sr, Finding.check_name).all():
        if not _in_target(_sl_of(sr_txt)["sl"], target_sl) or chk in excluded:
            continue
        sev_status[(sev or "info").lower()][(st or "open").lower()] += n

    # ---- findings in scope: always open + acknowledged; closed findings get their
    # own section when include_closed (owner 2026-10-14), never the main tables
    statuses = STATUSES if include_closed else ["open", "acknowledged"]
    # Explicit columns (not the entity) so the report still works against a
    # database that is a migration or two behind the models.
    rows = sf(db.query(*[getattr(Finding, c) for c in _FINDING_COLS]), Finding) \
             .filter(Finding.status.in_(["open", "acknowledged"])) \
             .order_by(Finding.created_at.desc(), Finding.id.desc()).all()
    findings = [d for d in (_finding_dict(f) for f in rows)
                if _in_target(d["sl"], target_sl) and d["check_name"] not in excluded]
    # SF: false positives - the operator's judgement, with the reason - are
    # reported in their own section, never among the findings in scope
    fp_rows = sf(db.query(*[getattr(Finding, c) for c in _FP_COLS]), Finding) \
                .filter(Finding.status == FALSE_POSITIVE) \
                .order_by(Finding.false_positive_at.desc(), Finding.id.desc()).all()
    false_positives = []
    for f in fp_rows:
        d = _finding_dict(f)
        d.update(reason=f.false_positive_reason, marked_by=f.false_positive_by, marked_at=f.false_positive_at)
        if _in_target(d["sl"], target_sl) and d["check_name"] not in excluded:
            false_positives.append(d)
    false_positives.sort(key=lambda f: _sev_rank(f["severity"]))
    closed_findings, closed_total = [], 0
    if include_closed:
        cq = sf(db.query(*[getattr(Finding, c) for c in _CLOSED_COLS]), Finding) \
               .filter(Finding.status == "closed") \
               .order_by(Finding.closed_at.desc().nulls_last(), Finding.id.desc())
        for f in cq.all():
            d = _finding_dict(f)
            if not _in_target(d["sl"], target_sl) or d["check_name"] in excluded:
                continue
            closed_total += 1
            if len(closed_findings) < _MAX_CLOSED:
                d.update(closed_at=f.closed_at, closed_by=f.acknowledged_by, notes=f.notes, last_seen=f.last_seen)
                closed_findings.append(d)
    # severity order (critical, high, medium, low, info), newest first within
    # a severity: the query's order is kept by the stable sort
    findings.sort(key=lambda f: _sev_rank(f["severity"]))

    # ---- catalogue / coverage
    catalogue = check_catalogue()
    above_target = sorted(k for k, v in catalogue.items() if not _in_target(v["sl"], target_sl))
    inputs = _input_counts(db, b, site_id)
    by_check: dict[str, list] = defaultdict(list)
    for f in findings:
        by_check[f["check_name"] or ""].append(f)
    observed_other = sorted(k for k in by_check if k and k not in catalogue)

    # owner 2026-10-12: PASS / NOT EVALUATED from the recorded evaluations
    # (app/check_evaluations.py); checks it does not track keep "no findings"
    from app.check_evaluations import config_evidence, coverage_states
    from app.models import Site
    scope_sites = [site_id] if site_id is not None else [r[0] for r in db.query(Site.id).all()]
    try:
        evals = coverage_states(db, scope_sites, catalogue, inputs)
        cfg_evidence = config_evidence(db, scope_sites)
    except Exception:  # pragma: no cover - table missing on an old schema
        db.rollback()
        evals, cfg_evidence = {}, []
    coverage = []
    for name, info in catalogue.items():
        if not _in_target(info["sl"], target_sl) or name in excluded:
            continue
        needed = _inputs_for(name, info)
        missing = [i for i in needed if not inputs.get(i)]
        n = len(by_check.get(name, []))
        basis = None
        if n:
            state = "findings"
        elif missing:
            state = "no data"
        else:
            ev = evals.get(name)
            state, basis = (ev["state"], ev["basis"]) if ev else ("no findings", None)
        coverage.append(dict(check_name=name, count=n, state=state, basis=basis,
                             missing=[_INPUT_LABELS.get(m, m) for m in missing], **info))
    coverage.sort(key=lambda c: (_checklist_sort_key(c["checklist_id"]), c["check_name"]))

    # ---- grouping: section -> check -> findings
    sections: dict[str, dict[str, list]] = defaultdict(lambda: defaultdict(list))
    for f in findings:
        name = f["check_name"] or ""
        ref = catalogue.get(name)
        cl = (ref or {}).get("checklist_id") or f["checklist_id"]
        sections[section_of(cl)][name].append(f)

    # ---- attestations (checklist 1.1-1.6)
    cutoff = now - timedelta(days=ATTESTATION_STALE_DAYS)
    attestations = []
    q = sf(db.query(*[getattr(Attestation, c) for c in _ATT_COLS]), Attestation) \
          .filter(Attestation.checklist_id.in_(list(ATTESTABLE_ROWS)))
    all_atts = q.order_by(Attestation.attested_at.desc(), Attestation.id.desc()).all()
    for row_id, desc in ATTESTABLE_ROWS.items():
        cands = [a for a in all_atts if a.checklist_id == row_id]
        if b is not None:
            scoped = [a for a in cands if a.baseline_id == b.id] or \
                     [a for a in cands if a.baseline_id is None]
        else:
            scoped = cands
        current = next((a for a in scoped if a.is_current), None)
        if current is None:
            status = "stale" if scoped else "missing"
            att = scoped[0] if scoped else None
        else:
            at = current.attested_at
            if at is not None and at.tzinfo is None:
                at = at.replace(tzinfo=timezone.utc)
            status = "current" if at is not None and at >= cutoff else "stale"
            att = current
        attestations.append({
            "checklist_id": row_id, "description": desc, "status": status,
            "attested_by": att.attested_by if att else None,
            "attested_at": att.attested_at if att else None,
            "notes": att.notes if att else None,
            "proof_filename": att.proof_filename if att else None,
            "open_findings": len([f for f in by_check.get(f"zone_doc_{row_id.replace('.', '_')}", [])
                                  if f["status"] == "open"]),
        })

    # ---- paired firewalls: vendor-diversity attestations (PF-<group id>)
    from app.models import Firewall, FirewallGroup
    for g in sf(db.query(FirewallGroup), FirewallGroup).filter(
            FirewallGroup.kind == "paired").order_by(FirewallGroup.id).all():
        cid = f"PF-{g.id}"
        members = sf(db.query(Firewall.name, Firewall.vendor), Firewall) \
            .filter(Firewall.paired_group_id == g.id).order_by(Firewall.id).all()
        cands = sf(db.query(*[getattr(Attestation, c) for c in _ATT_COLS]), Attestation) \
            .filter(Attestation.checklist_id == cid) \
            .order_by(Attestation.attested_at.desc(), Attestation.id.desc()).all()
        current = next((a for a in cands if a.is_current), None)
        at = current.attested_at if current is not None else None
        if at is not None and at.tzinfo is None:
            at = at.replace(tzinfo=timezone.utc)
        status = ("current" if at is not None and at >= cutoff
                  else "stale" if cands else "missing")
        att = current or (cands[0] if cands else None)
        attestations.append({
            "checklist_id": cid,
            "description": (f"Paired firewall {g.name} ({' + '.join(m.name for m in members)}): "
                            f"members are different vendors (manual; vendors recorded from "
                            f"configs: {', '.join(sorted({m.vendor or 'unknown' for m in members}))})"),
            "status": status,
            "attested_by": att.attested_by if att else None,
            "attested_at": att.attested_at if att else None,
            "notes": att.notes if att else None,
            "proof_filename": att.proof_filename if att else None,
            "open_findings": len([f for f in by_check.get("paired_firewall_vendor_diversity", [])
                                  if f["status"] == "open"
                                  and (f.get("detail") or {}).get("paired_group_id") == g.id]),
        })

    # ---- firewall inventory
    rule_counts: dict[Any, Counter] = defaultdict(Counter)
    for dev_id, enabled, n in sf(db.query(FirewallRule.firewall_device_id, FirewallRule.enabled,
                                          func.count(FirewallRule.id)), FirewallRule) \
                                .group_by(FirewallRule.firewall_device_id, FirewallRule.enabled).all():
        rule_counts[dev_id]["active" if enabled or enabled is None else "disabled"] += n
    # DR-07: logical policies (an expanded policy is many rows); rows without
    # a policy id (ACL lines) count one each.
    _pol_seen: set = set()
    for dev_id, enabled, vdom, pid, rid in sf(db.query(FirewallRule.firewall_device_id, FirewallRule.enabled,
                                                       FirewallRule.vdom, FirewallRule.policy_id,
                                                       FirewallRule.id), FirewallRule).all():
        key = (dev_id, vdom, pid) if pid is not None else (dev_id, "row", rid)
        if key in _pol_seen:
            continue
        _pol_seen.add(key)
        rule_counts[dev_id]["active_pol" if enabled or enabled is None else "disabled_pol"] += 1
    nat_counts: dict[Any, int] = {}
    if NatRule is not None:
        try:
            nat_counts = dict(sf(db.query(NatRule.firewall_device_id, func.count(NatRule.id)), NatRule)
                                .group_by(NatRule.firewall_device_id).all())
        except Exception:  # pragma: no cover - nat_rules table absent on old schema
            db.rollback()
            nat_counts = {}
    devices = []
    for d in sf(db.query(*[getattr(FirewallDevice, c) for c in _DEV_COLS]), FirewallDevice) \
               .order_by(FirewallDevice.name.asc()).all():
        devices.append({
            "id": d.id, "name": d.name, "vendor": d.vendor, "hostname": d.device_hostname,
            "firmware": d.firmware_version, "zone_from": d.purdue_zone_from,
            "zone_to": d.purdue_zone_to,
            "active_rules": rule_counts[d.id]["active"],
            "disabled_rules": rule_counts[d.id]["disabled"],
            "active_policies": rule_counts[d.id]["active_pol"],
            "disabled_policies": rule_counts[d.id]["disabled_pol"],
            "nat_rules": nat_counts.get(d.id, 0),
        })
    unassigned = rule_counts.get(None, Counter())

    # ---- declared management networks (operator decisions the management
    # checks rely on - docs/management-networks.md)
    management_networks = []
    try:
        from app.models import ManagementNetwork
        fw_names = dict(sf(db.query(Firewall.id, Firewall.name), Firewall).all())
        for m in sf(db.query(ManagementNetwork), ManagementNetwork) \
                .order_by(ManagementNetwork.kind, ManagementNetwork.id).all():
            purpose = m.purpose or "management"
            if m.kind in ("subnet", "host"):
                what = m.cidr
                detail = (m.label or "") if m.kind == "subnet" else \
                    {"jump_host": "jump host", "engineering_ws": "engineering workstation"}.get(
                        m.role, "admin workstation")
            elif m.kind == "vlan":
                what, detail = f"VLAN {m.vlan_id}", m.label or ""
            else:
                what = f"{m.name} on {fw_names.get(m.firewall_id, 'every firewall')}"
                detail = f"{purpose} zone" if m.is_management else \
                    "neither a management nor an engineering zone"
            management_networks.append({
                "kind": m.kind, "purpose": purpose if (m.kind != "name" or m.is_management) else None,
                "what": what, "detail": detail, "created_by": m.created_by,
                "created_at": m.created_at, "finding_id": m.finding_id, "note": m.note})
    except Exception:  # pragma: no cover - table absent on an old schema
        db.rollback()
        management_networks = []

    # ---- permitted communication paths (Access Review selection), one
    # enumeration per site
    access_paths = collect_access_path_sections(db, site_id, catalogue)

    # ---- MP-24: permit policies the rule-level reviews could not judge
    rules_not_judged = {"firewalls": [], "total_rules": 0, "not_judged": 0}
    try:
        from app.parsers.alert_engine import rules_not_judged as _rnj
        if site_id is not None:
            rules_not_judged = _rnj(db, site_id=site_id)
        else:
            from app.models import Site as _Site
            agg = {"firewalls": [], "total_rules": 0, "not_judged": 0}
            for sid in [r[0] for r in db.query(_Site.id).order_by(_Site.id)]:
                part = _rnj(db, site_id=sid)
                agg["firewalls"] += part["firewalls"]
                agg["total_rules"] += part["total_rules"]
                agg["not_judged"] += part["not_judged"]
            rules_not_judged = agg
    except Exception:  # never lose the report over this section
        log.exception("rules-not-judged section failed")

    zones = None
    if include_zones:
        try:
            zones = collect_zone_data(db, site_id, findings)
        except Exception:  # never lose the report over this section
            log.exception("zones-and-conduits section failed")
            zones = None

    return {
        "zones": zones,
        "access_paths": access_paths,
        "details": _report_details(db, site_id),
        "scope": {"firewalls": [d.get("hostname") or d["name"] for d in devices], "networks": _scope_networks(db, site_id)},
        "generated_at": now, "site": site, "site_id": site_id, "site_code": site_code,
        "target_sl": target_sl, "above_target": above_target,
        "excluded_checks": _rc.excluded_summary(db, site_id, excluded),
        "excluded_check_names": sorted(excluded),
        "baseline": baseline_info,
        "include_closed": include_closed, "statuses": statuses,
        "sev_status": {k: dict(v) for k, v in sev_status.items()},
        "findings": findings, "false_positives": false_positives,
        "closed_findings": closed_findings, "closed_total": closed_total,
        "sections": {k: dict(v) for k, v in sections.items()},
        "catalogue": catalogue, "coverage": coverage, "observed_other": observed_other,
        "config_evidence": cfg_evidence,
        "inputs": inputs, "attestations": attestations,
        "firewall_devices": devices,
        "management_networks": management_networks,
        "rules_not_judged": rules_not_judged,
        "unassigned_rules": {"active": unassigned["active"], "disabled": unassigned["disabled"]},
        "max_per_check": MAX_FINDINGS_PER_CHECK,
    }


# ---------------------------------------------------------------------------
# Page templates (cover vs. normal)
# ---------------------------------------------------------------------------
PAGE_W, PAGE_H = A4
MARGIN = 2 * cm
HEADER_H = 1.2 * cm
FOOTER_H = 0.8 * cm
CONTENT_W = PAGE_W - 2 * MARGIN


def _wordmark(canvas, x, y, size=9):
    """The IACS Monitor wordmark (navy "IACS", teal "Monitor")."""
    canvas.setFont("Helvetica-Bold", size)
    canvas.setFillColor(NAVY)
    canvas.drawString(x, y, "IACS")
    canvas.setFillColor(TEAL)
    canvas.drawString(x + canvas.stringWidth("IACS", "Helvetica-Bold", size) + 2, y, "Monitor")


def _draw_cover(canvas, doc):
    """Owner 2026-10-18: the cover of the sample report - a navy panel with a
    diagonal cut, the wordmark in a teal box, the title and the Prepared For /
    Project / Author / Date block; classification and version in the footer."""
    c = getattr(doc, "_iasc_cover", None) or {}
    canvas.saveState()
    p = canvas.beginPath()
    p.moveTo(0, PAGE_H); p.lineTo(0.62 * PAGE_W, PAGE_H); p.lineTo(0.42 * PAGE_W, 0.45 * PAGE_H); p.lineTo(0, 0.45 * PAGE_H); p.close()
    canvas.setFillColor(NAVY)
    canvas.drawPath(p, fill=1, stroke=0)
    logo = c.get("logo")                     # owner 2026-10-25: the audit checklist report puts the LRQA logo here
    if logo:
        canvas.drawImage(str(logo), 1.5 * cm, PAGE_H - 6.4 * cm, width=3.3 * cm, height=3.3 * cm, preserveAspectRatio=True, mask="auto")
    else:
        canvas.setStrokeColor(TEAL); canvas.setLineWidth(2)
        canvas.rect(1.5 * cm, PAGE_H - 5.6 * cm, 3.6 * cm, 2.3 * cm, stroke=1, fill=0)
        canvas.setFont("Helvetica-Bold", 13)
        canvas.setFillColor(WHITE); canvas.drawString(1.9 * cm, PAGE_H - 4.7 * cm, "IACS")
        canvas.setFillColor(TEAL); canvas.drawString(1.9 * cm + canvas.stringWidth("IACS", "Helvetica-Bold", 13) + 3, PAGE_H - 4.7 * cm, "Monitor")
    canvas.setFillColor(WHITE); canvas.setFont("Helvetica-Bold", 17)
    lines = tuple(c.get("title_lines") or ("IEC 62443 Firewall", "Audit"))[:3]     # the audit checklist report sets its own
    for i, line in enumerate(lines):
        canvas.drawString(1.5 * cm, PAGE_H - (7.6 + 0.8 * i) * cm, str(line)[:40])
    y = PAGE_H - 9.8 * cm
    for k, v in (("Prepared For:", c.get("client") or "—"), ("Project:", c.get("project") or "—"),
                 ("Author:", c.get("author") or "IACS_Monitor"), ("Date:", c.get("date") or "")):
        canvas.setFont("Helvetica-Bold", 8.5); canvas.drawString(1.5 * cm, y, k)
        canvas.setFont("Helvetica", 8.5)
        canvas.drawString(1.5 * cm + canvas.stringWidth(k, "Helvetica-Bold", 8.5) + 4, y, str(v)[:70])
        y -= 0.55 * cm
    canvas.setFillColor(colors.black); canvas.setFont("Helvetica", 7.5)
    canvas.drawString(1.5 * cm, 1.3 * cm, str(c.get("classification") or "Confidential Security Data (CSD)")[:80])
    canvas.drawRightString(PAGE_W - 1.5 * cm, 1.3 * cm, f"Version {c.get('version') or '1.0'}"[:40])
    canvas.restoreState()


def _draw_header_footer(canvas, doc):
    """Called on every normal page (not the cover): wordmark, classification, page number."""
    c = getattr(doc, "_iasc_cover", None) or {}
    canvas.saveState()
    _wordmark(canvas, MARGIN, 1.3 * cm)
    canvas.setFillColor(colors.black); canvas.setFont("Helvetica", 7.5)
    canvas.drawCentredString(PAGE_W / 2, 1.3 * cm, str(c.get("classification") or "Confidential Security Data (CSD)")[:80])
    canvas.drawRightString(PAGE_W - MARGIN, 1.3 * cm, str(doc.page))
    canvas.restoreState()


def _draw_header_footer_public(canvas, doc):
    """The public compliance report (the layout before 2026-10-18): navy header bar, footer line."""
    canvas.saveState()
    canvas.setFillColor(NAVY)
    canvas.rect(0, PAGE_H - HEADER_H - 5 * mm, PAGE_W, HEADER_H + 5 * mm, fill=1, stroke=0)
    canvas.setFillColor(WHITE)
    canvas.setFont("Helvetica-Bold", 9)
    canvas.drawString(MARGIN, PAGE_H - HEADER_H + 1 * mm, "OT Firewall Security Review")
    canvas.setFont("Helvetica", 9)
    canvas.drawRightString(PAGE_W - MARGIN, PAGE_H - HEADER_H + 1 * mm, f"Page {doc.page}")
    canvas.setFont("Helvetica", 8)
    canvas.drawString(MARGIN + 5 * cm, PAGE_H - HEADER_H + 1 * mm, "ISA/IEC 62443 Compliance Assessment Report")
    canvas.setFillColor(DARK_GREY)
    canvas.setFont("Helvetica", 7.5)
    site = getattr(doc, "_iasc_site", None)
    footer = "CONFIDENTIAL — Generated by IACS_Monitor | ISA/IEC 62443"
    if site:
        footer += f" | {site[:60]}"
    canvas.drawCentredString(PAGE_W / 2, 0.5 * cm, footer)
    canvas.setStrokeColor(MID_GREY)
    canvas.line(MARGIN, 1.1 * cm, PAGE_W - MARGIN, 1.1 * cm)
    canvas.restoreState()


LAYOUTS = ("lrqa", "public")       # lrqa = the LRQA compliance report (the template); public = the previous layout


def _build_templates(doc, layout: str = "lrqa"):
    cover_frame = Frame(MARGIN, MARGIN, PAGE_W - 2 * MARGIN, PAGE_H - 2 * MARGIN, id="cover_frame")
    if layout == "public":
        normal_frame = Frame(MARGIN, FOOTER_H + 1.2 * cm, PAGE_W - 2 * MARGIN,
                             PAGE_H - 2 * MARGIN - HEADER_H - 5 * mm, id="normal_frame")
        doc.addPageTemplates([
            PageTemplate(id="Cover", frames=[cover_frame]),
            PageTemplate(id="Normal", frames=[normal_frame], onPage=_draw_header_footer_public),
        ])
        return
    normal_frame = Frame(MARGIN, 2.2 * cm, PAGE_W - 2 * MARGIN, PAGE_H - 2.2 * cm - 1.8 * cm, id="normal_frame")
    doc.addPageTemplates([
        PageTemplate(id="Cover", frames=[cover_frame], onPage=_draw_cover),
        PageTemplate(id="Normal", frames=[normal_frame], onPage=_draw_header_footer),
    ])


_LAYOUT = {"public": False}
_RENDER_LOCK = threading.Lock()


def _set_layout(layout: str) -> None:
    """Switch the shared styles between the template (teal) and the public (navy) look."""
    public = layout == "public"
    _LAYOUT["public"] = public
    for st_ in (H2, H3, WU_LABEL):
        st_.textColor = NAVY if public else TEAL
    H2.fontName = H3.fontName = "Helvetica-Bold" if public else "Helvetica"
    HEAD_CELL.textColor = WHITE if public else TEAL
    HEAD_CELL.fontName = "Helvetica-Bold" if public else "Helvetica"


class _ReportDoc(BaseDocTemplate):
    """Collects the numbered section headings (style IASCH1) for the Contents page."""

    def afterFlowable(self, flowable):
        if isinstance(flowable, Paragraph) and getattr(flowable.style, "name", "") == "IASCH1":
            self.notify("TOCEntry", (0, esc(flowable.getPlainText(), None), self.page))


# ---------------------------------------------------------------------------
# Styles
# ---------------------------------------------------------------------------
_styles = getSampleStyleSheet()


def _style(name="Normal", **kw):
    return ParagraphStyle(name, parent=_styles[name], **kw)


H1 = ParagraphStyle("IASCH1", fontName="Helvetica", fontSize=20, leading=24, textColor=colors.black,
                    spaceAfter=10, spaceBefore=4)
H2 = _style("Heading2", fontName="Helvetica", fontSize=14, textColor=TEAL,
            spaceAfter=6, spaceBefore=12)
H3 = _style("Heading3", fontName="Helvetica", fontSize=11.5, textColor=TEAL,
            spaceAfter=4, spaceBefore=8)
TOC_STYLE = ParagraphStyle("toc0", fontName="Helvetica-Bold", fontSize=11, leading=22)
CAPTION = _style("Normal", fontName="Helvetica-Oblique", fontSize=7.5, leading=10, textColor=DARK_GREY, alignment=1)
BODY = _style("Normal", fontName="Helvetica", fontSize=9, leading=13,
              textColor=colors.black, spaceAfter=4)
SMALL = _style("Normal", fontName="Helvetica", fontSize=8, leading=11, textColor=DARK_GREY)
COVER_TITLE = _style("Normal", fontName="Helvetica-Bold", fontSize=28, leading=34,
                     textColor=NAVY, spaceAfter=6)
COVER_SUB = _style("Normal", fontName="Helvetica", fontSize=14, leading=18,
                   textColor=DARK_GREY, spaceAfter=4)
HEAD_CELL = _style("Normal", fontName="Helvetica", fontSize=8.5, leading=11, textColor=TEAL)
CELL = _style("Normal", fontName="Helvetica", fontSize=8, leading=10.5)
CELL_BOLD = _style("Normal", fontName="Helvetica-Bold", fontSize=8, leading=10.5)
CELL_SMALL = _style("Normal", fontName="Helvetica", fontSize=7.2, leading=9.2, textColor=DARK_GREY)
CHECK_HEAD = _style("Normal", fontName="Helvetica-Bold", fontSize=10, leading=13, textColor=NAVY)
WU_LABEL = _style("Normal", fontName="Helvetica-Bold", fontSize=8.5, leading=11, textColor=TEAL)
WU_CODE = _style("Code", fontName="Courier", fontSize=7.4, leading=9.4, backColor=LIGHT_GREY, leftIndent=4)


def _p(text, style=BODY):
    """Paragraph from TRUSTED markup (callers pass esc()'d data only)."""
    return Paragraph(text, style)


def _sp(h=0.25):
    return Spacer(1, h * cm)


def _hr(color=MID_GREY, thickness=0.5):
    return HRFlowable(width="100%", thickness=thickness, color=color, spaceAfter=4, spaceBefore=4)


def _sev_cell(sev: str, style=CELL_BOLD):
    sev = sev if sev in SEV_COLOUR else "info"
    return Paragraph(f'<font color="#{SEV_COLOUR[sev].hexval()[2:]}">{esc(sev.upper())}</font>', style)


def _grid_table(rows, col_widths, header=True, zebra=True, extra=None, repeat=1):
    tbl = Table(rows, colWidths=col_widths, repeatRows=repeat if header else 0)
    cmds = [
        ("FONTNAME", (0, 0), (-1, -1), "Helvetica"),
        ("FONTSIZE", (0, 0), (-1, -1), 8),
        ("GRID", (0, 0), (-1, -1), 0.3, MID_GREY),
        ("TOPPADDING", (0, 0), (-1, -1), 3),
        ("BOTTOMPADDING", (0, 0), (-1, -1), 3),
        ("VALIGN", (0, 0), (-1, -1), "TOP"),
    ]
    if header and _LAYOUT["public"]:
        cmds += [("BACKGROUND", (0, 0), (-1, 0), NAVY), ("TEXTCOLOR", (0, 0), (-1, 0), WHITE)]
    elif header:
        cmds += [("BACKGROUND", (0, 0), (-1, 0), WHITE), ("LINEBELOW", (0, 0), (-1, 0), 0.6, TEAL)]
    if zebra and len(rows) > 1:
        cmds.append(("ROWBACKGROUNDS", (0, 1 if header else 0), (-1, -1), [WHITE, LIGHT_GREY]))
    tbl.setStyle(TableStyle(cmds + list(extra or [])))
    return tbl


def _heads(*labels):
    return [Paragraph(esc(lbl), HEAD_CELL) for lbl in labels]


# ---------------------------------------------------------------------------
# Sections
# ---------------------------------------------------------------------------
def target_sl_text(target_sl: Optional[int]) -> str:
    from app.security_levels import SL_LABELS
    if target_sl is None:
        return "all levels (SL1-SL4)"
    return (f"{SL_LABELS.get(target_sl, f'SL{target_sl}')} (checks whose ISA/IEC 62443-3-3 requirements first "
            f"apply above SL {target_sl} are excluded)")


def _cover_fields(data: dict) -> dict:
    d = data.get("details") or {}
    site = data.get("site") or "(all sites)"
    return {"client": d.get("client_name") or site, "project": d.get("project_name") or (f"{site} ({data['site_code']})" if data.get("site_code") else site),
            "author": d.get("author") or "IACS_Monitor", "date": fmt_dt(data["generated_at"])[:10],
            "classification": d.get("classification") or "Confidential Security Data (CSD)", "version": d.get("version") or "1.0"}


def build_cover(data: dict) -> list:
    """The cover is drawn on the canvas (_draw_cover); the story only turns the page."""
    return [_sp(0.1), NextPageTemplate("Normal"), PageBreak()]


def build_cover_public(data: dict) -> list:
    """The cover of the public compliance report (the layout before 2026-10-18)."""
    story = [_sp(1.5)]
    story.append(_p("<b>IACS_Monitor</b>", _style("Normal", fontName="Helvetica-Bold", fontSize=11, textColor=NAVY)))
    story.append(_p("Industrial Automation Security Compliance Monitor", SMALL))
    story.append(_sp(2))
    story.append(_hr(NAVY, 2))
    story.append(_sp(0.4))
    story.append(_p("OT Firewall Security Review", COVER_TITLE))
    story.append(_p("ISA/IEC 62443 Compliance Assessment Report", COVER_SUB))
    story.append(_sp(0.4))
    story.append(_hr(MID_GREY, 0.5))
    story.append(_sp(1.5))
    b = data.get("baseline")
    d = data.get("details") or {}
    scope = ", ".join(data["statuses"])
    fields = [("Site Name:", data.get("site") or "(not specified)")]
    if data.get("site_code"):
        fields.append(("Site Code:", data["site_code"]))
    if d.get("client_name"):
        fields.append(("Prepared For:", d["client_name"]))
    fields += [
        ("Generated:", fmt_dt(data["generated_at"])),
        ("Findings in scope:", f"{len(data['findings'])} ({scope})"
                               + (f"; {len(data.get('false_positives') or [])} false positive(s), listed separately"
                                  if data.get("false_positives") else "")),
        ("Target Security Level:", target_sl_text(data.get("target_sl"))),
        ("Audit Baseline:", (f"{b['name']}" + (" (active)" if b["is_active"] else "")) if b else "(none)"),
        ("Prepared By:", d.get("author") or "IACS_Monitor"),
        ("Version:", d.get("version") or "1.0"),
        ("Classification:", d.get("classification") or "CONFIDENTIAL"),
    ]
    rows = [[Paragraph(esc(k), CELL_BOLD), Paragraph(esc(v, 200), CELL)] for k, v in fields]
    tbl = Table(rows, colWidths=[4.5 * cm, 11 * cm])
    tbl.setStyle(TableStyle([("TEXTCOLOR", (0, 0), (0, -1), DARK_GREY), ("BOTTOMPADDING", (0, 0), (-1, -1), 6),
                             ("TOPPADDING", (0, 0), (-1, -1), 6), ("LINEBELOW", (0, 0), (-1, -2), 0.3, MID_GREY),
                             ("VALIGN", (0, 0), (-1, -1), "MIDDLE")]))
    story.append(tbl)
    story.append(_sp(2))
    story.append(_hr(NAVY, 1))
    story.append(_sp(0.5))
    story.append(_p("This report is produced automatically by IACS_Monitor from its database and is intended for "
                    "authorised security personnel only. Handle in accordance with your organisation's information "
                    "security policy.", _style("Normal", fontName="Helvetica-Oblique", fontSize=8.5, textColor=DARK_GREY)))
    story.append(NextPageTemplate("Normal"))
    story.append(PageBreak())
    return story


def build_findings_public(data: dict) -> list:
    """The findings section of the public compliance report: grouped by area and check, one
    write-up per check (concern / why / remediation / FortiOS example / closes) with the
    affected-devices table (the 2026-10-17 layout)."""
    story = [_p("Findings", H2)]
    story.append(_p(
        "Findings are grouped by area and by the check that produced them. Each check is written up once: "
        "the concern, why it is a finding, the remediation (with the FortiOS settings that remediate it where "
        "the finding comes from a FortiGate configuration) and when it closes, followed by every affected "
        "firewall or device of the site with the policies, interfaces, VLANs, subnets, accounts and hosts the "
        "findings name, the highest severity and the status counts. The references name the IEC 62443 "
        "requirement and the NIST / CIS best practice the check follows.", BODY))
    if not data["findings"]:
        story += [_p("<i>No findings in scope.</i>", BODY), PageBreak()]
        return story
    catalogue = data["catalogue"]
    widths = [3.3 * cm, 4.2 * cm, 3.4 * cm, 3.6 * cm, 2.5 * cm]
    for sec in sorted(data["sections"], key=lambda s: (s == "?", int(s) if s.isdigit() else 0)):
        checks = data["sections"][sec]
        story.append(_p(esc(SECTION_NAMES.get(sec, "Other")), H3))
        ordered = sorted(checks.items(), key=lambda kv: (
            min(_sev_rank(f["severity"]) for f in kv[1]),
            _checklist_sort_key((catalogue.get(kv[0]) or {}).get("checklist_id") or kv[1][0]["checklist_id"]), kv[0]))
        for name, fl in ordered:
            ref = catalogue.get(name) or {}
            sr = ref.get("sr") or fl[0]["isa62443_sr"] or ""
            sev_c = Counter(f["severity"] for f in fl)
            sev_txt = ", ".join(f"{sev_c[s]} {s}" for s in SEVERITIES if sev_c.get(s))
            block, w = _writeup_block(name, sr, fl)
            devs = {f.get("device_name") or "—" for f in fl}
            head = [_p(esc(fmt_check_name(name)) + f' <font size="8" color="#555555">({esc(name or "no check name")})</font>', CHECK_HEAD),
                    _p(f"<b>Findings:</b> {len(fl)} ({esc(sev_txt)}) on {len(devs)} device{'s' if len(devs) != 1 else ''}", SMALL),
                    _p("<b>References:</b> " + esc("; ".join(w["references"]), 700), SMALL)]
            rows = [_heads("Firewall / device", "Policies", "Interfaces / VLANs / subnets", "Hosts", "Severity · status")]
            for r in _affected_rows(fl):
                rows.append([Paragraph(esc(r["device"], 80), CELL), Paragraph(_joined(r["policies"]), CELL_SMALL),
                             Paragraph(_joined(r["where"]), CELL_SMALL), Paragraph(_joined(r["hosts"]), CELL_SMALL),
                             Paragraph(f'<font color="#{SEV_COLOUR.get(r["severity"], NAVY).hexval()[2:]}"><b>{esc(r["severity"])}</b></font>'
                                       f'<br/>{r["count"]} finding{"s" if r["count"] != 1 else ""}: {esc(r["status"])}', CELL_SMALL)])
            sev = min((f["severity"] for f in fl), key=_sev_rank)
            tbl = _grid_table(rows, widths, extra=[("LINEABOVE", (0, 0), (-1, 0), 1.2, SEV_COLOUR.get(sev, NAVY))])
            if len(rows) <= 4 and not w.get("forti"):
                story.append(KeepTogether(head + [_sp(0.1), block, _sp(0.12), tbl]))
            else:
                story += [KeepTogether(head + [_sp(0.1), block])] + [_sp(0.12), tbl]
            story.append(_sp(0.4))
    story.append(PageBreak())
    return story


def build_story_public(data: dict) -> list:
    """The public compliance report: the layout before the technical template (2026-10-17)."""
    if data.get("rollup"):
        return build_rollup_story(data, "public")
    story = build_cover_public(data)
    story += [_p("Executive Summary", H2)] + build_executive_summary(data)[1:]
    story += build_findings_public(data)
    story += build_false_positives(data)
    story += build_closed_findings(data)
    story += build_excluded_checks(data)
    story += build_attestation(data)
    story += build_zones(data)
    story += build_firewall_inventory(data)
    story += build_shadow_rules(data)
    story += build_access_paths(data)
    story += build_coverage(data)
    story += build_config_evidence(data)
    story += build_control_mapping(data)
    return story


def build_contents(data: dict) -> list:
    toc = TableOfContents()
    toc.levelStyles = [TOC_STYLE]
    toc.dotsMinLevel = 9
    site = data.get("site") or "the site"
    story = [_p("Contents", _style("Normal", fontName="Helvetica", fontSize=18, leading=22, textColor=TEAL, spaceAfter=12)), toc, _sp(1)]
    story.append(_p(esc(f"The contents of this report belong to {site}. The findings, information and recommendations in this "
                        "document are for information purposes only and are based on a point-in-time assessment of the firewall "
                        "configurations, logs and captures within scope. IACS_Monitor is a passive monitor: it changes no device. "
                        "Review every recommendation, assess the risk and follow change control before remediation work is carried out."), SMALL))
    story.append(PageBreak())
    return story


def _people_table(rows: list) -> Table:
    t = [_heads("Name", "Role", "Email")]
    for r in rows:
        t.append([Paragraph(esc(r.get("name") or "—", 80), CELL), Paragraph(esc(r.get("role") or "", 80), CELL), Paragraph(esc(r.get("email") or "", 120), CELL)])
    if len(t) == 1:
        t.append([Paragraph("—", CELL), Paragraph("", CELL), Paragraph("", CELL)])
    return _grid_table(t, [5.5 * cm, 4.5 * cm, 7 * cm], zebra=False)


def build_distribution(data: dict) -> list:
    d = data.get("details") or {}
    dist = d.get("distribution") or []
    client = [r for r in dist if (r.get("side") or "client") != "assessor"]
    assessor = [r for r in dist if r.get("side") == "assessor"]
    if not assessor and (d.get("author") or d.get("author_email")):
        assessor = [{"name": d.get("author") or "", "role": "Author", "email": d.get("author_email") or ""}]
    story = [_p("1&nbsp;&nbsp;Distribution List", H1),
             _p(esc(f"{d.get('client_name') or data.get('site') or 'Client'} - points of contact"), H3), _people_table(client),
             _p("Assessor", H3), _people_table(assessor), _sp(0.6)]
    return story


def build_revisions(data: dict) -> list:
    d = data.get("details") or {}
    revs = d.get("revisions") or []
    rows = [_heads("Version", "Issue Date", "Status")]
    for r in revs:
        rows.append([Paragraph(esc(r.get("version") or "", 20), CELL), Paragraph(esc(r.get("date") or "", 40), CELL), Paragraph(esc(r.get("status") or "", 80), CELL)])
    if not revs:
        rows.append([Paragraph(esc(d.get("version") or "1.0"), CELL), Paragraph(esc(fmt_dt(data["generated_at"])[:10]), CELL), Paragraph("Generated", CELL)])
    return [_p("2&nbsp;&nbsp;Revision History", H1), _grid_table(rows, [3 * cm, 5 * cm, 9 * cm], zebra=False), PageBreak()]


def build_particulars(data: dict) -> list:
    """3 Engagement Particulars: background, scope, window / constraints, finding summary."""
    d = data.get("details") or {}
    site = data.get("site") or "(all sites)"
    scope = data.get("scope") or {}
    inp = data.get("inputs") or {}
    story = [_p("3&nbsp;&nbsp;Engagement Particulars", H1), _p("Background", H3),
             _p(esc(f"This report is the technical documentation of the IEC 62443 firewall audit of {site}. IACS_Monitor evaluated the "
                    "uploaded firewall configurations, firewall and syslog events, captured network sessions and the device inventory "
                    "against the ISA/IEC 62443 security requirements and the OT firewall review checklist. Nothing was changed on any device."), BODY),
             _p("Scope", H3)]
    rows = [_heads("Description", "Component")]

    def _lines(items, empty):       # owner 2026-10-18: one component per line
        return "<br/>".join(esc(x, 160) for x in items) if items else esc(empty)
    fws = scope.get("firewalls") or []
    rows.append([Paragraph("Firewalls", CELL), Paragraph(_lines(fws, "none uploaded"), CELL)])
    nets = scope.get("networks") or []
    rows.append([Paragraph("Networks", CELL), Paragraph(_lines(nets, "none known"), CELL)])
    b = data.get("baseline")
    inputs = [f"{_INPUT_LABELS[k]}: {v}" for k, v in inp.items() if k in _INPUT_LABELS and k != "baseline"]
    inputs.append(f"baseline: {b['name']}" if b else "baseline: none")
    rows.append([Paragraph("Inputs", CELL), Paragraph(_lines(inputs, "none"), CELL)])
    rows.append([Paragraph("Target security level", CELL), Paragraph(esc(target_sl_text(data.get("target_sl"))), CELL)])
    story.append(_grid_table(rows, [4 * cm, 13 * cm], zebra=False))
    story.append(_p("Assessment Window, Observations and Constraints", H3))
    story.append(_p(esc(d.get("constraints") or f"Data as uploaded up to {fmt_dt(data['generated_at'])[:10]}. No constraints were recorded on the Reports page.", 4000), BODY))
    nj = data.get("rules_not_judged")
    if isinstance(nj, dict) and nj.get("count"):
        story.append(_p(esc(f"{nj['count']} rule(s) on interfaces without a Purdue label are reported as direction unverified and not judged."), BODY))
    story.append(_p("Finding Summary", H3))
    n_checks = sum(len(v) for v in data["sections"].values())
    sev_checks = Counter(min((f["severity"] for f in fl), key=_sev_rank) for ch in data["sections"].values() for fl in ch.values())
    sev_find = Counter(f["severity"] for f in data["findings"])
    story.append(_p(esc(f"IACS_Monitor identified {n_checks} finding(s) - checks with open findings, {len(data['findings'])} individual "
                        "occurrences - in the scope. The following table shows the categorisation by severity (checks / occurrences):"), BODY))
    cells = [Paragraph(f'<font color="#{SEV_COLOUR[sv].hexval()[2:]}" size="18"><b>{sev_checks.get(sv, 0)}</b></font>'
                       f'<font size="9"> / {sev_find.get(sv, 0)}</font><br/><font size="8">{esc(sv.title())}</font>',
                       _style("Normal", fontName="Helvetica", fontSize=9, leading=14, alignment=1)) for sv in SEVERITIES]
    t = Table([cells], colWidths=[17 * cm / 5] * 5)
    t.setStyle(TableStyle([("BOX", (0, 0), (-1, -1), 0.5, MID_GREY), ("INNERGRID", (0, 0), (-1, -1), 0.5, MID_GREY),
                           ("TOPPADDING", (0, 0), (-1, -1), 8), ("BOTTOMPADDING", (0, 0), (-1, -1), 8)]))
    story.append(t)
    story.append(_sp(0.3))
    story += build_executive_summary(data)
    return story


def build_executive_summary(data: dict) -> list:
    story = [_p("Executive Summary", H3)]
    n = len(data["findings"])
    cov = data["coverage"]
    with_f = sum(1 for c in cov if c["state"] == "findings")
    no_data = sum(1 for c in cov if c["state"] == "no data")
    passed = sum(1 for c in cov if c["state"] == "pass")
    not_eval = sum(1 for c in cov if c["state"] == "not evaluated")
    other = len(cov) - with_f - no_data - passed - not_eval
    story.append(_p(
        f"IACS_Monitor evaluates firewall configuration, firewall/syslog events, observed "
        f"network sessions and device inventory against the ISA/IEC 62443-3-3 Security "
        f"Requirements (SR) and the OT firewall review checklist. This report covers "
        f"<b>{n}</b> finding{'s' if n != 1 else ''} with status {esc(' / '.join(data['statuses']))}. "
        f"Of the <b>{len(cov)}</b> implemented checks, <b>{with_f}</b> currently have findings "
        f"in scope, <b>{passed}</b> passed (evaluated on the current data, nothing found), "
        f"<b>{not_eval}</b> were not evaluated since the latest data, <b>{no_data}</b> lack the "
        f"input data they need"
        + (f" and <b>{other}</b> show no findings without a recorded evaluation" if other else "")
        + " (see Check Coverage).", BODY))
    if data.get("include_closed"):
        story.append(_sp(0.15))
        story.append(_p(f"<b>{data.get('closed_total', 0)} closed finding(s)</b> are listed in their own section "
                        "(Closed Findings) and are not counted among the findings in scope.", BODY))
    if data.get("excluded_checks"):
        n_ex = sum(len(g["checks"]) for g in data["excluded_checks"])
        story.append(_sp(0.15))
        story.append(_p(
            f"<b>{n_ex} check(s) excluded from this report</b> by the site ("
            + esc(", ".join(g["label"] + ("" if g["whole"] else f" ({len(g['checks'])} of {g['total']})")
                            for g in data["excluded_checks"]), 400)
            + "): their findings are not counted here - see Checks Excluded from this Report.", BODY))
    if data.get("target_sl") is not None:
        story.append(_sp(0.15))
        story.append(_p(
            f"<b>Target security level SL-T {data['target_sl']}.</b> "
            f"{len(data.get('above_target') or [])} check(s) whose requirements apply only above "
            f"SL {data['target_sl']} are excluded from the findings, the severity summary and "
            "coverage; they remain in the control mapping, marked above target.", BODY))
    if not (data.get("inputs") or {}).get("purdue_levels") and (data.get("inputs") or {}).get("rules"):
        lv = sum(1 for c in cov if c["state"] == "no data"
                 and "Purdue levels on firewall interfaces" in (c.get("missing") or []))
        story.append(_sp(0.15))
        story.append(_p(
            f"<b>No Purdue levels are assigned</b> to this site's firewall interfaces, so the "
            f"<b>{lv}</b> checks that judge IT/OT crossings, DMZ bypass, internet egress and "
            f"remote access into OT could not run. Their absence from this report is not a "
            f"pass: assign interface levels (FW Topology Builder) and re-run the reviews.", BODY))
    unp = [(sec.get("site"), u) for sec in (data.get("access_paths") or [])
           for u in (sec.get("unplaced_firewalls") or [])]
    if unp:
        story.append(_sp(0.15))
        story.append(_p(
            f"<b>{len(unp)}</b> firewall{'s' if len(unp) != 1 else ''} with rules "
            f"{'are' if len(unp) != 1 else 'is'} <b>not placed in the Purdue model</b>: "
            + esc("; ".join(f"{u.get('firewall') or '#' + str(u.get('firewall_id'))}"
                            + (f" ({site})" if site and len(data.get('access_paths') or []) > 1 else "")
                            + f" — {u.get('reason', '')}" for site, u in unp), 900)
            + ". Reachability, the permitted-path list and the chain findings do not see these "
              "firewalls; their absence from the findings is not a pass.", BODY))
    story.append(_sp(0.3))

    story.append(_p("Severity Summary (all findings"
                    + (f", in scope at SL-T {data['target_sl']})" if data.get("target_sl") is not None else ")"), H3))
    ss = data["sev_status"]
    cols = STATUSES + [FALSE_POSITIVE]
    rows = [_heads("Severity", "Open", "Acknowledged", "Closed", "False positive", "Total")]
    col_tot = Counter()
    extra = []
    for i, sev in enumerate(SEVERITIES, start=1):
        c = ss.get(sev, {})
        vals = [c.get(st, 0) for st in cols]
        for st, v in zip(cols, vals):
            col_tot[st] += v
        rows.append([_sev_cell(sev)] + [Paragraph(str(v), CELL) for v in vals]
                    + [Paragraph(str(sum(vals)), CELL_BOLD)])
    other = {k: v for k, v in ss.items() if k not in SEVERITIES}
    if other:
        vals = [sum(v.get(st, 0) for v in other.values()) for st in cols]
        for st, v in zip(cols, vals):
            col_tot[st] += v
        rows.append([Paragraph("Other", CELL_BOLD)] + [Paragraph(str(v), CELL) for v in vals]
                    + [Paragraph(str(sum(vals)), CELL_BOLD)])
    rows.append([Paragraph("Total", CELL_BOLD)]
                + [Paragraph(str(col_tot[st]), CELL_BOLD) for st in cols]
                + [Paragraph(str(sum(col_tot.values())), CELL_BOLD)])
    extra.append(("BACKGROUND", (0, -1), (-1, -1), TOTAL_BG))
    story.append(_grid_table(rows, [3.3 * cm, 2.1 * cm, 2.9 * cm, 2.1 * cm, 2.9 * cm, 2.1 * cm], extra=extra))
    story.append(_sp(0.4))

    # Per-area totals (in scope).  Owner 2026-10-17: no checklist numbers, no SR / FR / SL in the report;
    # the FR x SL matrix is not printed any more (build_fr_sl_matrix stays for the API).
    story.append(_p("Findings by Area (in scope)", H3))
    rows = [_heads("Area", "Checks with findings", *[s.title() for s in SEVERITIES], "Total")]
    for sec in sorted(data["sections"], key=lambda s: (s == "?", int(s) if s.isdigit() else 0)):
        checks = data["sections"][sec]
        sev_c = Counter(f["severity"] for fl in checks.values() for f in fl)
        rows.append([Paragraph(esc(SECTION_NAMES.get(sec, "Other")), CELL),
                     Paragraph(str(len(checks)), CELL)]
                    + [Paragraph(str(sev_c.get(s, 0)), CELL) for s in SEVERITIES]
                    + [Paragraph(str(sum(sev_c.values())), CELL_BOLD)])
    if len(rows) == 1:
        story.append(_p("No findings in scope.", BODY))
    else:
        story.append(_grid_table(rows, [4.6 * cm, 2.3 * cm] + [1.6 * cm] * 5 + [1.5 * cm]))

    # Priority list: checks with critical/high findings in scope
    prio = []
    for sec, checks in data["sections"].items():
        for name, fl in checks.items():
            top = min((SEVERITIES.index(f["severity"]) if f["severity"] in SEVERITIES else 4)
                      for f in fl)
            if top <= 1:
                prio.append((top, -len(fl), name, fl))
    if prio:
        prio.sort()
        story.append(_p("Remediation Priorities", H3))
        rows = [_heads("Check", "Reference", "Highest", "Findings")]
        for top, negn, name, fl in prio[:20]:
            ref = data["catalogue"].get(name, {})
            rows.append([Paragraph(esc(fmt_check_name(name)), CELL),
                         Paragraph(esc(_primary_reference(name, ref.get("sr") or fl[0]["isa62443_sr"])), CELL_SMALL),
                         _sev_cell(SEVERITIES[top]), Paragraph(str(-negn), CELL)])
        story.append(_grid_table(rows, [5.5 * cm, 6.5 * cm, 2 * cm, 2 * cm]))
    story.append(PageBreak())
    return story


def build_fr_sl_matrix(data: dict) -> list:
    """Findings in scope per foundational requirement x security level (a
    finding whose SRs span two FRs counts in each)."""
    from app.security_levels import FR_NAMES
    if not data["findings"]:
        return []
    cnt: dict[str, Counter] = defaultdict(Counter)
    for f in data["findings"]:
        key = f"SL{f['sl']}" if f.get("sl") else "none"
        for fr in (f.get("fr") or ["—"]):
            cnt[fr][key] += 1
    cols = ["SL1", "SL2", "SL3", "SL4"]
    story = [_p("Findings by Foundational Requirement and Security Level (in scope)", H3),
             _p("Security level = the lowest SL at which one of the finding's ISA/IEC 62443-3-3 "
                "requirements applies (62443-3-3 Annex B). \"—\" = no 62443-3-3 requirement "
                "(62443-2-1 programme items; in scope at every level).", SMALL)]
    rows = [_heads("Foundational requirement", *cols, "Total")]
    for fr in [*FR_NAMES, "—"]:
        c = cnt.get(fr)
        if not c:
            continue
        label = f"{fr} {FR_NAMES[fr]}" if fr in FR_NAMES else "— (no 62443-3-3 SR)"
        rows.append([Paragraph(esc(label), CELL)]
                    + [Paragraph(str(c.get(k, 0)), CELL) for k in cols]
                    + [Paragraph(str(sum(c.values())), CELL_BOLD)])
    story.append(_grid_table(rows, [7 * cm, 1.8 * cm, 1.8 * cm, 1.8 * cm, 1.8 * cm, 1.8 * cm]))
    story.append(_sp(0.4))
    return story


def _primary_reference(name: str, sr_text) -> str:
    from app.writeup import references
    refs = references(name, sr_text)
    return refs[0] if refs else "—"


_WHERE_KEYS = (("interface", "interface {}"), ("ot_interface", "OT interface {}"), ("it_interface", "IT interface {}"),
               ("vlan_id", "VLAN {}"), ("vlans", "VLAN {}"), ("segment", "segment {}"), ("network", "{}"), ("networks", "{}"),
               ("zone_a", "zone {}"), ("zone_b", "zone {}"), ("username", "account {}"), ("user", "account {}"),
               ("object", "{}"), ("tunnel", "tunnel {}"), ("vap", "SSID {}"), ("portal", "portal {}"))
_HOST_KEYS = ("ip", "host_ip", "src_ip", "dst_ip", "it_host_ip", "ot_host_ip")


def _affected_rows(fl: list) -> list:
    """Owner 2026-10-17: one entry per check per site - every firewall / device
    with the policies, interfaces, VLANs, subnets, accounts and hosts the
    findings name, the highest severity and the status counts."""
    by_dev: dict = {}
    for f in fl:
        d = f.get("detail")
        if isinstance(d, str):
            try:
                d = json.loads(d)
            except ValueError:
                d = {"description": d}
        d = d if isinstance(d, dict) else {}
        dev = f.get("device_name") or d.get("device_name") or d.get("firewall") or "—"
        e = by_dev.setdefault(dev, {"policies": [], "where": [], "hosts": [], "sev": [], "status": Counter(), "n": 0, "titles": []})
        e["n"] += 1
        if f.get("title") and f["title"] not in e["titles"]:
            e["titles"].append(f["title"])
        e["sev"].append(f.get("severity") or "info")
        e["status"][f.get("status") or "open"] += 1

        def _add(lst, v):
            v = str(v)
            if v and v not in lst:
                lst.append(v)
        if d.get("policy_id") not in (None, ""):
            _add(e["policies"], f"{d['policy_id']}" + (f" ({d['policy_name']})" if d.get("policy_name") else ""))
        for k in ("policy_id_a", "policy_id_b", "vpn_policy_id"):
            if d.get(k) not in (None, ""):
                _add(e["policies"], str(d[k]))
        if d.get("src_zone") or d.get("dst_zone"):
            _add(e["where"], f"{d.get('src_zone') or 'any'} → {d.get('dst_zone') or 'any'}")
        for k, fmt in _WHERE_KEYS:
            v = d.get(k)
            if v in (None, "", [], {}):
                continue
            if isinstance(v, (list, tuple)):
                for x in v[:6]:
                    _add(e["where"], fmt.format(x))
            elif not isinstance(v, dict):
                _add(e["where"], fmt.format(v))
        if d.get("src_ip") and d.get("dst_ip"):
            _add(e["hosts"], f"{d['src_ip']} → {d['dst_ip']}" + (f":{d['dst_port']}" if d.get("dst_port") else ""))
        else:
            for k in _HOST_KEYS:
                if d.get(k):
                    _add(e["hosts"], str(d[k]))
        if not d.get("ip") and d.get("mac") and not any(d.get(k) for k in _HOST_KEYS):
            _add(e["hosts"], str(d["mac"]))
    rows = []
    for dev, e in sorted(by_dev.items(), key=lambda kv: (min(_sev_rank(x) for x in kv[1]["sev"]), kv[0])):
        top = min(e["sev"], key=_sev_rank)
        if not (e["policies"] or e["where"] or e["hosts"]):
            e["where"] = e["titles"][:6]            # nothing structured in the evidence: the finding titles say where
        rows.append({"device": dev, "policies": e["policies"], "where": e["where"], "hosts": e["hosts"],
                     "severity": top, "count": e["n"],
                     "status": ", ".join(f"{n} {st}" for st, n in sorted(e["status"].items()))})
    return rows


def _joined(items: list, limit: int = 12, text_limit: int = 420) -> str:
    if not items:
        return "—"
    txt = ", ".join(items[:limit]) + (f" … +{len(items) - limit} more" if len(items) > limit else "")
    return esc(txt, text_limit)


def _writeup_block(name: str, sr_text, fl: list):
    """The write-up table: concern, why, remediation, FortiOS example, closes."""
    from app.writeup import writeup
    first = fl[0].get("detail") if fl else None
    if isinstance(first, str):
        try:
            first = json.loads(first)
        except ValueError:
            first = None
    w = writeup(name, sr_text, first if isinstance(first, dict) else None)
    rows = [[Paragraph("Concern", WU_LABEL), Paragraph(esc(w["concern"], 600), BODY)],
            [Paragraph("Why it is a finding", WU_LABEL), Paragraph(esc(w["why"], 1200), BODY)],
            [Paragraph("Remediation", WU_LABEL), Paragraph(esc(w["fix"], 1200), BODY)]]
    if w.get("forti"):
        rows.append([Paragraph("FortiOS example", WU_LABEL), Preformatted(w["forti"][:2400], WU_CODE, maxLineLength=84)])
    rows.append([Paragraph("Closes when", WU_LABEL), Paragraph(esc(w["closes"], 500), BODY)])
    t = Table(rows, colWidths=[3.0 * cm, 14.0 * cm])
    t.setStyle(TableStyle([("VALIGN", (0, 0), (-1, -1), "TOP"), ("LINEBELOW", (0, 0), (-1, -2), 0.3, MID_GREY),
                           ("LEFTPADDING", (0, 0), (-1, -1), 3), ("RIGHTPADDING", (0, 0), (-1, -1), 3),
                           ("TOPPADDING", (0, 0), (-1, -1), 2), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
    return t, w


def _analysis_entries(data: dict, prefix: str = "5") -> list:
    """[(number, name, findings, section)] in print order: by area, severity, checklist order."""
    catalogue = data["catalogue"]
    items = []
    for sec, checks in data["sections"].items():
        for name, fl in checks.items():
            items.append((min(_sev_rank(f["severity"]) for f in fl), (sec == "?", int(sec) if sec.isdigit() else 0),
                          _checklist_sort_key((catalogue.get(name) or {}).get("checklist_id") or fl[0]["checklist_id"]), name, fl, sec))
    items.sort(key=lambda x: x[:4])
    return [(f"{prefix}.{i}", name, fl, sec) for i, (_s, _a, _c, name, fl, sec) in enumerate(items, 1)]


def build_findings_summary(data: dict, num: str = "4", analysis_num: str = "5") -> list:
    """4 Findings: one row per check - title, highest severity, primary reference, analysis section."""
    story = [_p(f"{esc(num)}&nbsp;&nbsp;Findings", H1 if "." not in num else H2), _p(esc(data.get("site") or "All sites"), H3)]
    if not data["findings"]:
        story += [_p("<i>No findings in scope.</i>", BODY), PageBreak()]
        return story
    catalogue = data["catalogue"]
    rows = [_heads("Title", "Severity", "Reference", "Section")]
    for enum, name, fl, _sec in _analysis_entries(data, analysis_num):
        ref = catalogue.get(name) or {}
        top = min((f["severity"] for f in fl), key=_sev_rank)
        rows.append([Paragraph(esc(fmt_check_name(name)) + f' <font size="7" color="#555555">({len(fl)})</font>', CELL),
                     Paragraph(f'<font color="#{SEV_COLOUR.get(top, NAVY).hexval()[2:]}">{esc(top.title())}</font>', CELL),
                     Paragraph(esc(_primary_reference(name, ref.get("sr") or fl[0]["isa62443_sr"]), 90), CELL_SMALL),
                     Paragraph(esc(enum), CELL)])
    story.append(_grid_table(rows, [8.4 * cm, 2 * cm, 5 * cm, 1.6 * cm], zebra=False))
    story.append(_sp(0.2))
    story.append(_p(esc(f"One row per check: the same finding on several firewalls, policies or hosts is one line (the count in brackets); "
                        f"section {analysis_num} lists every affected component."), SMALL))
    story.append(PageBreak())
    return story


def _values_table(fl: list, limit: int = 10) -> Optional[Table]:
    """Configuration / observed values of the findings (owner 2026-10-18: no figures - the
    FortiOS values or the application data): device, finding, the evidence facts."""
    from app.explain import _FACTS, _fmt
    rows = [_heads("Device", "Finding", "Values")]
    for f in fl[:limit]:
        d = f.get("detail")
        if isinstance(d, str):
            try:
                d = json.loads(d)
            except ValueError:
                d = {"description": d}
        d = d if isinstance(d, dict) else {}
        facts = []
        for k, label in _FACTS:
            v = d.get(k)
            if v in (None, "", [], {}):
                continue
            facts.append(f"{label}: {_fmt(v)}")
            if len(facts) >= 7:
                break
        if not facts:
            facts = [evidence_summary(d, 300)] if d else []
        rows.append([Paragraph(esc(f.get("device_name") or "—", 60), CELL_SMALL), Paragraph(esc(f.get("title") or "", 200), CELL_SMALL),
                     Paragraph(esc("; ".join(facts), 420), CELL_SMALL)])
    if len(rows) == 1:
        return None
    return _grid_table(rows, [3 * cm, 5.5 * cm, 8.5 * cm], zebra=False)


def _sentences(text: str) -> list:
    parts = [x.strip() for x in re.split(r"(?<=[.;])\s+", text or "") if x.strip()]
    return [p[0].upper() + p[1:] for p in parts] or [text]


def build_findings(data: dict, num: str = "5") -> list:
    """5 Analysis: one entry per check (owner 2026-10-17 / 18) in the sample report's form."""
    story = [_p(f"{esc(num)}&nbsp;&nbsp;Analysis: {esc(data.get('site') or 'All sites')}", H1 if "." not in num else H2)]
    story.append(_p(
        "One entry per check, most severe first: the concern, why it is a finding, the configuration or observed values, "
        "the remediation (with the FortiOS settings that remediate it where "
        "the finding comes from a FortiGate configuration, filled from the finding where it names a policy, "
        "interface or account) and when it closes, followed by every affected firewall or device of the site "
        "with the policies, interfaces, VLANs, subnets, accounts and hosts the findings name, the highest "
        "severity and the status counts. The references name the IEC 62443 requirement and the NIST / CIS "
        "best practice the check follows."
        + (" Where the device is in an IEC 62443 zone, the findings are judged against its SL-T on the console; "
           "the counts here are unchanged." if (data.get("zones") or {}).get("judged") else ""), BODY))
    if not data["findings"]:
        story.append(_p("<i>No findings in scope.</i>", BODY))
        story.append(PageBreak())
        return story

    from app.writeup import writeup
    catalogue = data["catalogue"]
    widths = [3.3 * cm, 4.2 * cm, 3.4 * cm, 3.6 * cm, 2.5 * cm]
    for i, (enum, name, fl, sec) in enumerate(_analysis_entries(data, num)):
        ref = catalogue.get(name) or {}
        sr = ref.get("sr") or fl[0]["isa62443_sr"] or ""
        sev_c = Counter(f["severity"] for f in fl)
        sev_txt = ", ".join(f"{sev_c[s]} {s}" for s in SEVERITIES if sev_c.get(s))
        top = min((f["severity"] for f in fl), key=_sev_rank)
        first = fl[0].get("detail")
        if isinstance(first, str):
            try:
                first = json.loads(first)
            except ValueError:
                first = None
        w = writeup(name, sr, first if isinstance(first, dict) else None)
        devs = sorted({f.get("device_name") or "—" for f in fl})
        st_c = Counter(f.get("status") or "open" for f in fl)
        oldest = min((f.get("created_at") for f in fl if f.get("created_at")), default=None)
        head = _p(f'{esc(enum)} <font color="#{SEV_COLOUR.get(top, NAVY).hexval()[2:]}">{esc(top.title())}</font>: {esc(fmt_check_name(name))}', H2 if "." not in num else H3)
        meta = [[Paragraph("Check", CELL), Paragraph(esc(name), CELL)],
                [Paragraph("Area", CELL), Paragraph(esc(SECTION_NAMES.get(sec, "Other")), CELL)],
                [Paragraph("Findings", CELL), Paragraph(esc(f"{len(fl)} ({sev_txt}) on {len(devs)} device{'s' if len(devs) != 1 else ''} - "
                                                           + ", ".join(f"{n} {k}" for k, n in sorted(st_c.items()))), CELL)],
                [Paragraph("First seen", CELL), Paragraph(esc(fmt_dt(oldest)[:10] if oldest else "—"), CELL)],
                [Paragraph("Closes when", CELL), Paragraph(esc(w["closes"], 500), CELL)]]
        mt = Table(meta, colWidths=[3.2 * cm, 13.8 * cm])
        mt.setStyle(TableStyle([("GRID", (0, 0), (-1, -1), 0.4, MID_GREY), ("VALIGN", (0, 0), (-1, -1), "TOP"),
                                ("TOPPADDING", (0, 0), (-1, -1), 3), ("BOTTOMPADDING", (0, 0), (-1, -1), 3)]))
        named = [d for d in devs if d != "—"]
        where = f" on {', '.join(named)}" if named else " (no device named: a capture, inventory or attestation finding)"
        desc = [_p("Description of the Issue", H3)]
        if w["why"].strip().startswith(w["concern"].strip().rstrip(".")):
            desc.append(_p(esc(w["why"], 1500), BODY))          # the concern is the first sentence of the why text
        else:
            desc += [_p(esc(w["concern"], 600), BODY), _p(esc(w["why"], 1500), BODY)]
        desc.append(_p(esc(f"IACS_Monitor found {len(fl)} occurrence{'s' if len(fl) != 1 else ''}{where}."), BODY))
        vt = _values_table(fl)
        values = [_p("Configuration / Observed Values", H3), vt, _p(esc(f"Table: values recorded with the findings ({min(len(fl), 10)} of {len(fl)})"), CAPTION)] if vt is not None else []
        rows = [_heads("Firewall / device", "Policies", "Interfaces / VLANs / subnets", "Hosts", "Severity · status")]
        for r in _affected_rows(fl):
            rows.append([
                Paragraph(esc(r["device"], 80), CELL),
                Paragraph(_joined(r["policies"]), CELL_SMALL),
                Paragraph(_joined(r["where"]), CELL_SMALL),
                Paragraph(_joined(r["hosts"]), CELL_SMALL),
                Paragraph(f'<font color="#{SEV_COLOUR.get(r["severity"], NAVY).hexval()[2:]}"><b>{esc(r["severity"])}</b></font>'
                          f'<br/>{r["count"]} finding{"s" if r["count"] != 1 else ""}: {esc(r["status"])}', CELL_SMALL),
            ])
        affected = [_p("Affected Components", H3), _grid_table(rows, widths, zebra=False)]
        recs = [_p("IACS_Monitor Recommends", H3)] + [_p(f"{i}.&nbsp;&nbsp;{esc(sx, 600)}", BODY) for i, sx in enumerate(_sentences(w["fix"]), 1)]
        forti = [_p("FortiOS Example", H3), Preformatted(w["forti"][:2400], WU_CODE, maxLineLength=104)] if w.get("forti") else []
        reading = [_p("Further Reading", H3)] + [_p("•&nbsp;&nbsp;" + esc(r, 300), BODY) for r in w["references"]]
        if i > 0:
            story.append(PageBreak())          # owner 2026-10-18: every analysis entry starts on a new page
        story.append(KeepTogether([head, mt] + desc))
        story += values + affected + recs + forti + reading
    story.append(PageBreak())
    return story


_ATT_COLOUR = {"current": OK_GREEN, "stale": SEV_COLOUR["high"], "missing": SEV_COLOUR["critical"]}


def build_false_positives(data: dict) -> list:
    """SF: the findings the operator marked false positives, with the reason,
    who and when.  They stay out of every other count and table."""
    fps = data.get("false_positives") or []
    story = [_p("False Positives", H2),
             _p("Findings the operator judged wrong, with the reason recorded. A false positive is "
                "never raised again as a new finding (a persisting condition updates it silently) and "
                "is excluded from the findings in scope, the severity summary and the coverage "
                "counts. Review the reasons: they are the assessor's attestation that the condition "
                "does not apply.", BODY)]
    if not fps:
        story.append(_p("<i>No findings are marked false positive.</i>", BODY))
        story.append(PageBreak())
        return story
    rows = [_heads("Severity", "Check", "Finding", "Device", "Reason", "Marked by / on")]
    for f in fps:
        rows.append([
            _sev_cell(f["severity"], CELL_BOLD),
            Paragraph(esc(fmt_check_name(f["check_name"])), CELL_SMALL),
            Paragraph(esc(f["title"], 300), CELL),
            Paragraph(esc(f["device_name"], 80), CELL_SMALL),
            Paragraph(esc(f.get("reason") or "", 600), CELL),
            Paragraph(esc(f.get("marked_by") or "") + "<br/>" + esc(fmt_dt(f.get("marked_at"))[:10]), CELL_SMALL),
        ])
    story.append(_grid_table(rows, [1.9 * cm, 2.8 * cm, 4.5 * cm, 2 * cm, 3.9 * cm, 1.9 * cm]))
    story.append(PageBreak())
    return story


def build_closed_findings(data: dict) -> list:
    """Owner 2026-10-14: with "Include closed findings", closed findings are listed in
    their own section (closed date, who, notes) - never among the findings in scope."""
    if not data.get("include_closed"):
        return []
    rows_in = data.get("closed_findings") or []
    total = data.get("closed_total", len(rows_in))
    story = [_p("Closed Findings", H2),
             _p(f"<b>{total}</b> finding(s) closed (resolved by the operator, or auto-resolved when a review "
                "no longer reproduced the condition), newest first. They are not counted among the findings in "
                "scope, the coverage or the sections above; the severity summary's Closed column counts them."
                + (f" The first {len(rows_in)} are listed." if total > len(rows_in) else ""), BODY)]
    if not rows_in:
        story.append(_p("<i>No closed findings.</i>", BODY))
        story.append(PageBreak())
        return story
    rows = [_heads("Severity", "Check", "Finding", "Device", "Closed on / by", "Notes")]
    for f in rows_in:
        rows.append([
            _sev_cell(f["severity"], CELL_BOLD),
            Paragraph(esc(fmt_check_name(f["check_name"])), CELL_SMALL),
            Paragraph(esc(f["title"], 300), CELL),
            Paragraph(esc(f["device_name"], 80), CELL_SMALL),
            Paragraph(esc(fmt_dt(f.get("closed_at"))[:10] if f.get("closed_at") else "—")
                      + (f'<br/><font size="7" color="#555555">{esc(f["closed_by"], 40)}</font>' if f.get("closed_by") else ""), CELL_SMALL),
            Paragraph(esc(f.get("notes") or "", 400) or "—", CELL_SMALL),
        ])
    story.append(_grid_table(rows, [1.9 * cm, 2.8 * cm, 4.5 * cm, 2 * cm, 2.1 * cm, 3.7 * cm]))
    story.append(PageBreak())
    return story


def build_excluded_checks(data: dict) -> list:
    """Owner 2026-10-14: the groups / checks the site left out of this report
    (Reports page, "Checks in the report"), with the open findings left out and
    the reasons.  Only when something is excluded."""
    groups = data.get("excluded_checks") or []
    if not groups:
        return []
    n_checks = sum(len(g["checks"]) for g in groups)
    n_find = sum(g["open_findings"] for g in groups)
    story = [_p("Checks Excluded from this Report", H2),
             _p(f"The site excluded <b>{n_checks}</b> check(s) from this report "
                f"({n_find} open or acknowledged finding(s) of them are not listed). Their findings still "
                "exist in the monitor (Findings page, exports); they are left out of the findings, the "
                "severity summary and the coverage of this report. Whole groups are listed by name.", BODY)]
    rows = [_heads("Group", "Excluded checks", "Open findings left out", "Reason", "By / on")]
    for g in groups:
        if g["whole"]:
            what = f"<b>all {g['total']} checks</b>"
        else:
            what = "<br/>".join(esc(fmt_check_name(c["check_name"])) for c in g["checks"])
        reasons = sorted({c.get("reason") for c in g["checks"] if c.get("reason")})
        by = sorted({c.get("excluded_by") for c in g["checks"] if c.get("excluded_by")})
        when = max((c.get("excluded_at") for c in g["checks"] if c.get("excluded_at")), default=None)
        rows.append([
            Paragraph(f"<b>{esc(g['label'])}</b>", CELL),
            Paragraph(what, CELL_SMALL),
            Paragraph(str(g["open_findings"]), CELL),
            Paragraph("<br/>".join(esc(r, 300) for r in reasons) or "—", CELL_SMALL),
            Paragraph(esc(", ".join(by)) + ("<br/>" + esc(fmt_dt(when)[:10]) if when else ""), CELL_SMALL),
        ])
    story.append(_grid_table(rows, [3.6 * cm, 4.6 * cm, 2.0 * cm, 4.6 * cm, 2.2 * cm]))
    story.append(PageBreak())
    return story


def build_attestation(data: dict) -> list:
    story = [_p("Zone Documentation Attestation (Checklist 1.1–1.6)", H2)]
    b = data.get("baseline")
    story.append(_p(
        "Section 1 controls require human review of policy and design artifacts. A row is "
        f"satisfied by a current attestation less than {ATTESTATION_STALE_DAYS} days old"
        + (f" for baseline <b>{esc(b['name'])}</b> (or with no baseline)" if b else "")
        + ". Attestations are recorded at /ui/attestation.", BODY))
    rows = [_heads("Row", "Control", "Status", "Attested by / at", "Notes / proof", "Open findings")]
    extra = []
    for i, a in enumerate(data["attestations"], start=1):
        col = _ATT_COLOUR[a["status"]]
        who = esc(a["attested_by"], 80) + ("<br/>" + esc(fmt_dt(a["attested_at"])) if a["attested_at"] else "")
        notes = esc(a["notes"], 200)
        if a["proof_filename"]:
            notes += ("<br/>" if notes else "") + "Proof: " + esc(a["proof_filename"], 80)
        rows.append([Paragraph(esc(a["checklist_id"]), CELL_BOLD),
                     Paragraph(esc(a["description"]), CELL),
                     Paragraph(f'<font color="#{col.hexval()[2:]}"><b>{esc(a["status"].upper())}</b></font>', CELL),
                     Paragraph(who or "—", CELL_SMALL),
                     Paragraph(notes or "—", CELL_SMALL),
                     Paragraph(str(a["open_findings"]), CELL)])
    story.append(_grid_table(rows, [1.1 * cm, 4.6 * cm, 1.9 * cm, 3.3 * cm, 4.3 * cm, 1.8 * cm], extra=extra))
    if b:
        story.append(_sp(0.3))
        story.append(_p(
            f"Baseline <b>{esc(b['name'])}</b>{' (active)' if b['is_active'] else ''}: "
            f"{b['comms_entries']} approved communications entries, "
            f"{b['approved_hosts']} approved hosts.", SMALL))
    story.append(_sp(0.4))
    return story


# ---------------------------------------------------------------------------
# Zones and Conduits (IEC 62443-3-2) - compact, next to the attestation
# ---------------------------------------------------------------------------
AMBER = colors.HexColor("#b9770e")
AMBER_BG = colors.HexColor("#fdf2e0")
ZONE_MAX_UNZONED = 60
H3K = _style("Heading3", fontName="Helvetica-Bold", fontSize=11, textColor=NAVY,
             spaceAfter=4, spaceBefore=8, keepWithNext=1)


def collect_zone_data(db, site_id: Optional[int], findings: list) -> Optional[dict]:
    """Zones, conduits, devices and unzoned hosts of the report's site, and
    a ``zone`` judgement on each finding dict (app/iec_zones.py).  None when
    the site has no zones.  A report without ``site_id`` uses the only site."""
    from app import iec_zones as iz
    from app.models import IecZone, Site
    if site_id is None:
        ids = [r[0] for r in db.query(Site.id).limit(2)]
        if len(ids) != 1:
            return None
        site_id = ids[0]
    if db.query(IecZone.id).filter(IecZone.site_id == site_id).first() is None:
        return None
    model = iz.ZoneModel(db, site_id)
    zones = iz.zone_summary(model)
    view = iz.conduit_view(db, model)
    judge = iz.FindingJudge(db, site_id)
    judge._devices = {d["id"]: d for d in view["devices"]}
    tally = {}
    for f in findings:
        j = judge.judge(f.get("detail"), f.get("device_name"), f.get("isa62443_sr"), f.get("check_name"))
        f["zone"] = j
        if not j:
            continue
        key = (j["via"], j.get("conduit") or j.get("firewall")
               or " ↔ ".join(sorted(j["zones"], key=str.lower) if j["via"] == "zones" else j["zones"]))
        t = tally.setdefault(key, {"via": j["via"], "scope": key[1], "sl_t": j["zone_sl_t"],
                                   "applies": Counter(), "beyond": 0, "no_sl_t": 0})
        if j["verdict"] == "applies":
            t["applies"][f["severity"]] += 1
        else:
            t[j["verdict"]] += 1
    return {"zones": zones, "conduits": view["conduits"], "undocumented": view["undocumented"],
            "devices": view["devices"], "unassigned": iz.unassigned_hosts(model),
            "overlaps": model.overlaps, "judged": sum(1 for f in findings if f.get("zone")),
            "tally": sorted(tally.values(), key=lambda t: ({"zone": 0, "conduit": 1, "zones": 2,
                                                            "firewall": 3}.get(t["via"], 9), t["scope"].lower()))}


def _sev_cell_shown(f: dict):
    """Severity cell of a findings row: the shown severity, one step lower on
    a documented conduit that covers the finding (option 3), with the
    recorded one underneath."""
    j = f.get("zone")
    if j and j.get("adjustment"):
        shown = {"critical": "high", "high": "medium", "medium": "low"}.get(f["severity"], f["severity"])
        if shown != f["severity"]:
            return Paragraph(f'<font color="#{SEV_COLOUR.get(shown, NAVY).hexval()[2:]}"><b>{esc(shown.upper())}</b></font>'
                             f'<br/><font size="6" color="#555555">↓ recorded {esc(f["severity"])}<br/>conduit</font>', CELL_BOLD)
    return _sev_cell(f["severity"], CELL_BOLD)


def _amber(text: str) -> str:
    return f'<font color="#b9770e"><b>{text}</b></font>'


def _slv(v, prefix: str) -> str:
    """Security level for a cell; SL0 is a level (owner 2026-10-13), None is "—"."""
    return f"{prefix} {v}" if v is not None else "—"


def zone_line(j: Optional[dict]) -> str:
    """Device-cell suffix: the finding's zone, its SL-T and the verdict."""
    if not j:
        return ""
    where = j.get("conduit") or (f"{j['firewall']} conduits" if j.get("firewall") else " ↔ ".join(j["zones"]))
    t = j.get("zone_sl_t")
    if j["verdict"] == "beyond":
        mark = _amber(f"▲ beyond SL-T {t}") + f' <font color="#555555">(SL{j.get("check_sl")} check)</font>'
    elif j["verdict"] == "no_sl_t":
        mark = '<font color="#555555">no SL-T</font>'
    else:
        mark = f"SL-T {t} ✓"
    doc = j.get("documentation")
    if doc == "undocumented":
        mark += " · " + _amber("no conduit")
    elif doc == "intra_zone":
        mark += " · in zone"
    if j.get("adjustment"):
        mark += f'<br/><font size="6" color="#555555">{esc(j["adjustment"], 160)}</font>'
    return f'<br/><font size="6.5" color="#1a2744">{esc(where, 80)}</font> <font size="6.5">· {mark}</font>'


def _sla_cell(sl_a, status, note=None) -> str:
    if sl_a is None:
        return '<font color="#555555">not assessed</font>'
    txt = f"SL-A {sl_a}"
    if status == "below":
        txt = _amber(txt + " ▼")
    if note:
        txt += f'<br/><font size="6.5" color="#555555">{esc(note, 60)}</font>'
    return txt


def build_zones(data: dict) -> list:
    z = data.get("zones")
    if not z or not z.get("zones"):
        return []
    zones, conduits, und = z["zones"], z["conduits"], z["undocumented"]
    s = [_p("Zones and Conduits (IEC 62443)", H2)]
    s.append(_p(
        "The zones and conduits documented for this site. A zone groups assets with common security "
        "requirements and carries a target security level (SL-T) and, once assessed, an achieved level "
        "(SL-A); it can span several Purdue levels and networks. SL-C is the capability of a component "
        "(IEC 62443-4-2). An SL-A or SL-C below the SL-T is a gap to close or to cover with compensating "
        "countermeasures (shaded amber).", BODY))
    s.append(_p("<i>Documentation only: zones never change which findings are raised, their severities or the "
                "Purdue levels the checks use. Device findings are judged against their zone's SL-T below and in "
                "the findings tables.</i>", SMALL))
    n_hosts = sum(x["host_count"] for x in zones)
    s.append(_p(f"<b>{len(zones)}</b> zones · <b>{n_hosts}</b> hosts in zones · "
                f"<b>{len(z['unassigned'])}</b> hosts in no zone · <b>{len(conduits)}</b> documented conduits · "
                f"<b>{len(und)}</b> zone pairs communicating without one", SMALL))

    rows = [_heads("Zone", "SL-T", "SL-A", "Purdue levels", "Hosts", "SL-C assessed", "Lowest SL-C", "Below SL-T")]
    extra = []
    for i, x in enumerate(zones, start=1):
        below = len(x["sl_c"]["below_target"])
        rows.append([
            Paragraph(f"<b>{esc(x['name'])}</b>" + (f'<br/><font size="6.5" color="#555555">{esc(x["owner"], 40)}</font>'
                                                   if x.get("owner") else ""), CELL),
            Paragraph(_slv(x["sl_t"], "SL-T"), CELL),
            Paragraph(_sla_cell(x.get("sl_a"), x.get("sl_a_status"), x.get("sl_a_note")), CELL_SMALL),
            Paragraph(" ".join(f"L{lv:g}" for lv in x["purdue_levels"]) or "—", CELL),
            Paragraph(str(x["host_count"]), CELL),
            Paragraph(f"{x['sl_c']['assessed']} of {x['host_count']}", CELL),
            Paragraph(_slv(x["sl_c"]["min"], "SL-C"), CELL),
            Paragraph(_amber(str(below)) if below else "0", CELL),
        ])
        if x.get("sl_a_status") == "below":
            extra.append(("BACKGROUND", (2, i), (2, i), AMBER_BG))
        if below:
            extra.append(("BACKGROUND", (7, i), (7, i), AMBER_BG))
    s.append(_p("Zones", H3K))
    s.append(_grid_table(rows, [3.6 * cm, 1.3 * cm, 2.4 * cm, 2.2 * cm, 1.3 * cm, 2.1 * cm, 2.0 * cm, 2.1 * cm],
                         extra=extra))
    for x in zones:
        for n in x["sl_c"]["notes"][:1]:
            s.append(_p(_amber("▲ ") + f"<b>{esc(x['name'])}:</b> " + esc(n), CELL_SMALL))

    if z.get("tally"):
        s.append(_p("Device findings judged against the zone SL-T", H3K))
        rows = [_heads("Zone / conduit", "SL-T", "Apply at SL-T", "Beyond SL-T", "No SL-T")]
        extra = []
        for i, t in enumerate(z["tally"], start=1):
            ap = t["applies"]
            ap_txt = ", ".join(f"{ap[sv]} {sv}" for sv in SEVERITIES if ap.get(sv)) or "0"
            kind = {"zone": "", "conduit": "conduit ", "zones": "no conduit: ", "firewall": "firewall "}[t["via"]]
            rows.append([Paragraph(f'<font color="#555555">{kind}</font>{esc(t["scope"], 90)}', CELL),
                         Paragraph(_slv(t["sl_t"], "SL-T"), CELL), Paragraph(ap_txt, CELL),
                         Paragraph(_amber(str(t["beyond"])) if t["beyond"] else "0", CELL),
                         Paragraph(str(t["no_sl_t"]), CELL)])
            if t["beyond"]:
                extra.append(("BACKGROUND", (3, i), (3, i), AMBER_BG))
        s.append(_grid_table(rows, [6.0 * cm, 1.5 * cm, 5.3 * cm, 2.2 * cm, 2.0 * cm], extra=extra))
        s.append(_p("A finding is judged against the SL-T of its device's zone; a finding between two zones against "
                    "the documented conduit's SL-T (else the higher zone SL-T); a firewall finding against the "
                    "highest SL-T of the conduits it carries. <b>Beyond</b>: the check's 62443-3-3 requirement first "
                    "applies above that SL-T. The owner rule that no OT device has direct Internet access applies "
                    "at every SL-T.", SMALL))

    devs = [d for d in z["devices"] if d["conduits"] or d["sl_c"] is not None]
    if devs:
        s.append(_p("Firewalls and routing switches", H3K))
        rows = [_heads("Device", "SL-C", "Source", "Documented conduits carried (target)", "Gap")]
        extra = []
        for i, d in enumerate(devs, start=1):
            rows.append([
                Paragraph(f"<b>{esc(d['name'])}</b>", CELL),
                Paragraph(_slv(d["sl_c"], "SL-C") if d["sl_c"] is not None else "not assessed", CELL),
                Paragraph(esc(d["sl_c_source"] or "—", 80), CELL_SMALL),
                Paragraph("<br/>".join(f"{esc(c['conduit'])} ({_slv(c['target_sl'], 'SL-T')})" for c in d["conduits"])
                          or "no documented conduit", CELL_SMALL),
                Paragraph(_amber(f"below SL-T {d['highest_target']}") if d["below_target"] else "—", CELL),
            ])
            if d["below_target"]:
                extra.append(("BACKGROUND", (4, i), (4, i), AMBER_BG))
        s.append(_grid_table(rows, [3.2 * cm, 1.8 * cm, 4.0 * cm, 5.6 * cm, 2.4 * cm], extra=extra))

    if conduits:
        s.append(_p("Documented conduits", H3K))
        rows = [_heads("Conduit", "Zones", "SL-T", "SL-A", "Firewalls (SL-C)", "Traffic", "Notes")]
        extra = []
        for i, c in enumerate(conduits, start=1):
            pol = c["a_to_b"]["policy_count"] + c["b_to_a"]["policy_count"]
            ses = c["a_to_b"]["sessions"] + c["b_to_a"]["sessions"]
            svcs = sorted(set(x.split(" ×")[0] for x in c["a_to_b"]["services"] + c["b_to_a"]["services"]))[:4]
            traffic = (f"{pol} polic{'y' if pol == 1 else 'ies'}, {ses} sessions"
                       + (f"<br/>{esc(', '.join(svcs))}" if svcs else "")) if pol or ses else "—"
            # owner 2026-10-13: the firewall rule numbers attached to the conduit
            rules = c.get("rules") or []
            if rules:
                traffic += ('<br/><font size="6.5" color="#1a2744">rules: '
                            + esc(", ".join(f"{r['firewall']} #{r['policy_id']}"
                                            + (" (deny)" if r.get("action") == "deny" else "") for r in rules[:8])
                                  + (" …" if len(rules) > 8 else ""), 200) + "</font>")
            fws = ", ".join(f"{esc(f['name'])} ({_slv(f['sl_c'], 'SL-C') if f['sl_c'] is not None else '?'})" for f in c["firewalls"])
            target = c.get("target_sl")
            rows.append([
                Paragraph(f"<b>{esc(c['name'] or '—')}</b>"
                          + (f'<br/><font size="6.5" color="#555555">services: {esc(c["services"], 80)}</font>' if c.get("services") else "")
                          + (f'<br/><font size="6.5" color="#555555">sources: {esc(c["sources"], 80)}</font>' if c.get("sources") else ""),
                          CELL_SMALL),
                Paragraph(f"{esc(c['zone_a']['name'])} ↔<br/>{esc(c['zone_b']['name'])}", CELL_SMALL),
                Paragraph(_slv(c["sl_t"], "SL-T") if c["sl_t"] is not None else (f"({_slv(target, 'SL-T')})" if target is not None else "—"), CELL),
                Paragraph(_sla_cell(c.get("sl_a"), c.get("sl_a_status"), c.get("sl_a_note")), CELL_SMALL),
                Paragraph(fws or "—", CELL_SMALL),
                Paragraph(traffic, CELL_SMALL),
                Paragraph("<br/>".join(_amber("▲ ") + esc(n) for n in c["notes"] + (c.get("rule_notes") or [])) or "—", CELL_SMALL),
            ])
            if c.get("sl_a_status") == "below":
                extra.append(("BACKGROUND", (3, i), (3, i), AMBER_BG))
            if c["notes"] or c.get("rule_notes"):
                extra.append(("BACKGROUND", (6, i), (6, i), AMBER_BG))
        s.append(_grid_table(rows, [2.6 * cm, 2.6 * cm, 1.3 * cm, 1.8 * cm, 2.3 * cm, 2.6 * cm, 3.8 * cm], extra=extra))

    s.append(_p("Communication without a documented conduit", H3K))
    if und:
        rows = [_heads("Zones", "Policies", "Sessions", "Main services")]
        extra = []
        for i, u in enumerate(und, start=1):
            svcs = sorted(set(x.split(" ×")[0] for x in u["a_to_b"]["services"] + u["b_to_a"]["services"]))[:5]
            rows.append([Paragraph(f"{esc(u['zone_a']['name'])} ↔ {esc(u['zone_b']['name'])}", CELL),
                         Paragraph(str(u["policy_count"]), CELL), Paragraph(str(u["sessions"]), CELL),
                         Paragraph(esc(", ".join(svcs)) or "—", CELL_SMALL)])
            if u.get("declarable"):
                extra.append(("BACKGROUND", (0, i), (0, i), AMBER_BG))
        s.append(_grid_table(rows, [6.4 * cm, 1.8 * cm, 1.8 * cm, 7.0 * cm], extra=extra))
        s.append(_p("Zone pairs with a permitting policy or observed traffic and no documented conduit, including "
                    "assets in no zone and the Internet. Shaded: two documented zones - document the conduit or "
                    "remove the path.", SMALL))
    else:
        s.append(_p("<i>None: every zone pair that communicates has a documented conduit.</i>", SMALL))

    un = z["unassigned"]
    if un:
        s.append(_p(f"Hosts in no zone ({len(un)})", H3K))
        s.append(_p(esc(", ".join(f"{h['ip']}" + (f" ({h['hostname']})" if h.get("hostname") else "")
                                  for h in un[:ZONE_MAX_UNZONED]), None)
                    + (f" … and {len(un) - ZONE_MAX_UNZONED} more (assets CSV export)" if len(un) > ZONE_MAX_UNZONED
                       else ""), CELL_SMALL))
    for o in z.get("overlaps") or []:
        s.append(_p(_amber("▲ ") + esc(f"{o['network']} is a member of {o['zones'][0]} and {o['zones'][1]}: "
                                       f"{o['note']}"), CELL_SMALL))
    s.append(_sp(0.2))
    s.append(_p("SL-T target, SL-A achieved (IEC 62443-3-2 / -3-3), SL-C capability of a component (IEC 62443-4-2). "
                "▼ below the target. ▲ gap to document. A conduit's target is its own SL-T, else (in brackets) the "
                "higher SL-T of its zones.", SMALL))
    s.append(_sp(0.4))
    return s


_SHADOW_TYPE_LABEL = {"duplicate": "Duplicate (redundant)", "full_shadow": "Fully shadowed",
                      "partial_shadow": "Partially shadowed"}


def _shadow_rule_cell(r: dict) -> str:
    """One rule of a shadow pair: policy id (vdom), name, action, match."""
    if not isinstance(r, dict):
        return "—"
    ident = str(r.get("policy_id") or r.get("rule_id") or "?")
    if r.get("vdom"):
        ident += f" (vdom {r['vdom']})"
    head = f"<b>#{esc(ident)}</b>" + (f" {esc(r.get('policy_name'), 40)}" if r.get("policy_name") else "")
    match = f"{r.get('src') or 'any'} → {r.get('dst') or 'any'} {r.get('protocol') or 'any'}/{r.get('dst_port') or 'any'}"
    return (head + f'<br/><font size="6.5">{esc(str(r.get("action") or "?").upper())} · {esc(match, 90)}</font>'
            + (f'<br/><font size="6.5" color="#555555">order {r["rule_order"]}</font>' if r.get("rule_order") is not None else ""))


def build_shadow_rules(data: dict) -> list:
    """Owner 2026-10-14: the shadowed, partially shadowed and duplicate (redundant)
    rule pairs in scope, one table per firewall - the shadow_rule findings laid out
    as rule pairs (they also appear under section 3 of the findings)."""
    rows_in = [f for f in data.get("findings") or [] if f.get("check_name") == "shadow_rule"]
    story = [_p("Shadowed and Redundant Rules", H2),
             _p("Rule pairs where an earlier rule matches some or all of a later rule's traffic (checklist 3.9, "
                "SR 7.7). <b>Fully shadowed</b>: the later rule can never fire - high when a deny is hidden by an "
                "earlier permit, medium when a dead permit is hidden by a deny. <b>Partially shadowed</b>: the earlier "
                "rule silently overrides the later one for the overlapping traffic (medium when a permit overrides "
                "part of a deny, low the other way). <b>Duplicate</b>: same traffic, same action - the later rule is "
                "redundant (low). The intended carve-out (a narrower rule before a wider one with the opposite "
                "action) is not reported. Rules whose interfaces or zones cannot overlap never shadow each other.", BODY)]
    if not rows_in:
        story.append(_p("<i>No shadowed or redundant rules among the findings in scope.</i>", BODY))
        story.append(PageBreak())
        return story
    by_dev: dict = {}
    for f in rows_in:
        d = f.get("detail") if isinstance(f.get("detail"), dict) else {}
        dev = f.get("device_name") or (d.get("shadowing_rule") or {}).get("device_name") or "(firewall)"
        by_dev.setdefault(dev, []).append((f, d))
    order = {"full_shadow": 0, "partial_shadow": 1, "duplicate": 2}
    for dev in sorted(by_dev, key=str.lower):
        pairs = sorted(by_dev[dev], key=lambda t: (order.get(t[1].get("shadow_type"), 3), _sev_rank(t[0]["severity"])))
        counts = Counter(d.get("shadow_type") for _f, d in pairs)
        story.append(_p(f"{esc(dev)}: {len(pairs)} pair(s) - "
                        + ", ".join(f"{n} {_SHADOW_TYPE_LABEL.get(k, k or 'other').lower()}" for k, n in counts.items()), H3))
        rows = [_heads("Earlier rule (wins)", "Later rule (shadowed / redundant)", "Type", "Severity", "Status")]
        extra = []
        for i, (f, d) in enumerate(pairs, start=1):
            rows.append([
                Paragraph(_shadow_rule_cell(d.get("shadowing_rule")), CELL_SMALL),
                Paragraph(_shadow_rule_cell(d.get("shadowed_rule")), CELL_SMALL),
                Paragraph(esc(_SHADOW_TYPE_LABEL.get(d.get("shadow_type"), d.get("shadow_type") or "?"))
                          + ("<br/>" + _amber("▲ actions differ") if d.get("action_conflict") else ""), CELL_SMALL),
                _sev_cell(f["severity"], CELL_BOLD),
                Paragraph(esc(str(f["status"]).replace("_", " ")), CELL_SMALL),
            ])
            if d.get("action_conflict"):
                extra.append(("BACKGROUND", (2, i), (2, i), AMBER_BG))
        story.append(_grid_table(rows, [5.0 * cm, 5.0 * cm, 2.8 * cm, 1.8 * cm, 2.4 * cm], extra=extra))
        story.append(_sp(0.2))
    story.append(PageBreak())
    return story


def build_firewall_inventory(data: dict) -> list:
    story = [_p("Firewall Inventory", H2)]
    devs = data["firewall_devices"]
    ua = data["unassigned_rules"]
    tot_a = sum(d.get("active_policies", d["active_rules"]) for d in devs) + ua.get("active_pol", ua["active"])
    tot_d = sum(d.get("disabled_policies", d["disabled_rules"]) for d in devs) + ua.get("disabled_pol", ua["disabled"])
    tot_rows = sum(d["active_rules"] + d["disabled_rules"] for d in devs) + ua["active"] + ua["disabled"]
    story.append(_p(
        f"<b>{len(devs)}</b> firewall device{'s' if len(devs) != 1 else ''}, <b>{tot_a}</b> active "
        f"and <b>{tot_d}</b> disabled policies / rules ({tot_rows} rows once address groups and "
        "services are expanded). Disabled rules enforce nothing and are reported "
        "for removal under checklist 3.8 (SR 7.7).", BODY))
    if devs or ua["active"] or ua["disabled"]:
        rows = [_heads("Device", "Vendor", "Hostname / firmware", "Purdue boundary",
                       "Active policies", "Disabled policies", "NAT rules")]
        for d in devs:
            # F-08: fmt_level renders the industrial DMZ as "L3.5" (never "L3.0")
            bnd = (f"{fmt_level(d['zone_from'])} → {fmt_level(d['zone_to'])}"
                   if d["zone_from"] is not None and d["zone_to"] is not None else "unassigned")
            hf = esc(d["hostname"], 60) + ("<br/>" + esc(d["firmware"], 60) if d["firmware"] else "")
            rows.append([Paragraph(esc(d["name"], 80), CELL_BOLD), Paragraph(esc(d["vendor"], 40), CELL),
                         Paragraph(hf or "—", CELL_SMALL), Paragraph(esc(bnd), CELL),
                         Paragraph(f'{d.get("active_policies", d["active_rules"])}'
                                   f'<br/><font size="7">{d["active_rules"]} rows</font>', CELL),
                         Paragraph(str(d.get("disabled_policies", d["disabled_rules"])), CELL),
                         Paragraph(str(d["nat_rules"]), CELL)])
        if ua["active"] or ua["disabled"]:
            rows.append([Paragraph("<i>(rules without a device)</i>", CELL), Paragraph("", CELL),
                         Paragraph("", CELL), Paragraph("", CELL),
                         Paragraph(str(ua.get("active_pol", ua["active"])), CELL),
                         Paragraph(str(ua.get("disabled_pol", ua["disabled"])), CELL), Paragraph("", CELL)])
        story.append(_grid_table(rows, [3.4 * cm, 2 * cm, 3.6 * cm, 2.3 * cm, 1.8 * cm, 2 * cm, 1.9 * cm]))
    else:
        story.append(_p("<i>No firewall configurations have been ingested.</i>", BODY))
    story += build_management_networks(data)
    story.append(PageBreak())
    return story


_MG_KIND = {"subnet": "Network", "host": "Trusted host", "vlan": "VLAN", "name": "Zone / interface"}


def build_management_networks(data: dict) -> list:
    """Declared management and engineering networks: the operator decisions
    behind the management / engineering checks (rows 2.5, 5.1, 5.5, 8.4, 9.5;
    SR 1.3, SR 2.1, SR 5.1 RE1)."""
    mn = data.get("management_networks") or []
    story = [_p("Declared Management &amp; Engineering Networks", H3)]
    if not mn:
        story.append(_p(
            "<i>No management or engineering networks are declared. The checks treat only the "
            "active baseline's admin workstations / jump hosts (management) and engineering "
            "workstations (engineering) as sources, and judge interfaces by their names.</i>", BODY))
        return story
    story.append(_p(
        f"<b>{len(mn)}</b> operator declaration{'s' if len(mn) != 1 else ''} of where privileged "
        "access legitimately comes from. <b>Management</b>: administering infrastructure "
        "(firewalls, switches, servers). <b>Engineering</b>: programming and configuring "
        "controllers and field devices at L0-L2 - approved only toward OT equipment and for "
        "industrial writes. Findings these declarations resolved are closed; removing a "
        "declaration brings them back.", BODY))
    rows = [_heads("Kind", "Purpose", "Declaration", "Detail", "Declared by", "From finding")]
    for m in mn:
        by = esc(m.get("created_by") or "—", 40)
        if m.get("created_at"):
            by += "<br/>" + esc(str(m["created_at"])[:10])
        rows.append([Paragraph(esc(_MG_KIND.get(m["kind"], m["kind"])), CELL),
                     Paragraph(esc(m.get("purpose") or "—"), CELL),
                     Paragraph(esc(m["what"], 80), CELL_BOLD),
                     Paragraph(esc(m.get("detail") or "", 120)
                               + ("<br/>" + esc(m["note"], 200) if m.get("note") else ""), CELL_SMALL),
                     Paragraph(by, CELL_SMALL),
                     Paragraph(f"#{m['finding_id']}" if m.get("finding_id") else "—", CELL)])
    story.append(_grid_table(rows, [2.4 * cm, 2.4 * cm, 3.8 * cm, 4.2 * cm, 2.6 * cm, 1.6 * cm]))
    return story


_STATE_COLOUR = {"findings": SEV_COLOUR["high"], "pass": OK_GREEN, "no findings": OK_GREEN,
                 "not evaluated": SEV_COLOUR["medium"], "no data": DARK_GREY}
_STATE_LABEL = {"findings": "FINDINGS", "pass": "PASS", "no findings": "no findings",
                "not evaluated": "NOT EVALUATED", "no data": "no data"}


def build_coverage(data: dict) -> list:
    story = [_p("Check Coverage", H2)]
    cov = data["coverage"]
    inp = data["inputs"]
    story.append(_p(
        "Every implemented check with its finding count in scope and its result. "
        "<b>PASS</b>: the check was evaluated on the current data and found nothing - the line under "
        "it says when and on what (the periodic review run, the FortiGate configurations, or the "
        "log events as they arrived). <b>NOT EVALUATED</b>: its review has not run completely "
        "since the latest data (upload, capture or declaration) - re-run the reviews. "
        "<b>no data</b>: the inputs it needs are absent, so it could not have produced a finding. "
        "<b>no findings</b>: nothing in scope, but no evaluation is recorded for the check "
        "(cross-firewall, switch and management-network checks).", BODY))
    story.append(_p(
        esc("Inputs present: " + ", ".join(f"{_INPUT_LABELS[k]}: {v}" for k, v in inp.items()
                                           if k in _INPUT_LABELS and k != "baseline")
            + f"; baseline: {'yes' if inp.get('baseline') else 'no'}", 600), SMALL))
    if data.get("target_sl") is not None:
        story.append(_p(esc(f"Target security level SL-T {data['target_sl']}: "
                            f"{len(data.get('above_target') or [])} check(s) above the target "
                            "are not listed."), SMALL))
    rows = [_heads("Area", "Check", "Reference", "Category", "Findings", "Result")]
    extra = []
    for i, c in enumerate(cov, start=1):
        col = _STATE_COLOUR[c["state"]]
        res = f'<font color="#{col.hexval()[2:]}"><b>{esc(_STATE_LABEL.get(c["state"], c["state"]))}</b></font>'
        if c["state"] == "no data" and c["missing"]:
            res += "<br/>" + esc("missing: " + ", ".join(c["missing"]))
        elif c.get("basis"):
            res += "<br/>" + esc(c["basis"], 220)
        rows.append([Paragraph(esc(SECTION_NAMES.get(section_of(c["checklist_id"]), "Other")), CELL_SMALL),
                     Paragraph(esc(c["check_name"]), CELL),
                     Paragraph(esc(_primary_reference(c["check_name"], c["sr"])), CELL_SMALL),
                     Paragraph(esc(fmt_category(c["category"])), CELL_SMALL),
                     Paragraph(str(c["count"]), CELL_BOLD if c["count"] else CELL),
                     Paragraph(res, CELL_SMALL)])
    story.append(_grid_table(rows, [2.6 * cm, 4.2 * cm, 4.6 * cm, 2 * cm, 1.4 * cm, 2.2 * cm],
                             extra=extra))
    rnj = data.get("rules_not_judged") or {}
    if rnj.get("not_judged"):
        story.append(_sp(0.3))
        story.append(_p(
            f"<b>Rules not judged by the rule-level reviews: {rnj['not_judged']} of "
            f"{rnj['total_rules']} permit policies.</b> A side of each resolves to no Purdue level "
            "(an interface or zone without a label, an unknown name, or no zone at all), so "
            "rule_it_ot_bypass, rule_mgmt_wrong_zone, rule_ot_it_dependency, rule_cleartext_protocol, "
            "rule_mgmt_protocol and rule_cleartext_creds could not evaluate it; its absence from the findings is not a "
            "pass. Label the interfaces named below and re-run the reviews.", BODY))
        rows = [_heads("Firewall", "Not judged / permits", "Why", "Policies (first 20)")]
        for e in rnj["firewalls"]:
            why = "; ".join(f"{k} ({v})" for k, v in sorted(e["reasons"].items()))
            pols = ", ".join(p["policy_id"] for p in e["policies"])
            rows.append([Paragraph(esc(e["firewall"] or "?", 60), CELL_BOLD),
                         Paragraph(f"{e['not_judged']} / {e['rules_total']}", CELL),
                         Paragraph(esc(why, 300), CELL_SMALL),
                         Paragraph(esc(pols, 400), CELL_SMALL)])
        story.append(_grid_table(rows, [3.4 * cm, 2.6 * cm, 5.5 * cm, 5.5 * cm]))
    if data["observed_other"]:
        story.append(_sp(0.3))
        story.append(_p("Other check names with findings in scope (inline SR metadata, e.g. "
                        "per-setting config checks):", SMALL))
        story.append(_p(esc(", ".join(data["observed_other"]), 2000), SMALL))
    story.append(PageBreak())
    return story


def build_config_evidence(data: dict) -> list:
    """Configuration Evidence (owner 2026-10-12): per FortiGate configuration, the
    settings its checks examined and the result - PASS, or the checks with an
    open / acknowledged finding on that firewall."""
    ev = data.get("config_evidence") or []
    if not ev:
        return []
    story = [_p("Configuration Evidence", H2)]
    story.append(_p(
        "The settings the configuration checks examined on each FortiGate, as read from its "
        "latest uploaded configuration, with the result of the checks that judge each setting: "
        "<b>PASS</b>, or the checks with a finding on that firewall (see Findings). A setting a "
        "backup leaves at its FortiOS default is shown as not set.", BODY))
    for e in ev:
        story.append(_sp(0.25))
        story.append(_p(f"<b>{esc(e['firewall'] or '?', 80)}</b>"
                        + (f" ({esc(e['device'], 80)})" if e.get("device") and e["device"] != e["firewall"] else "")
                        + f" — configuration evaluated {esc(fmt_dt(e['evaluated_at']))}", BODY))
        bad = set(e.get("open_checks") or [])
        rows = [_heads("Setting", "Value in the configuration", "Result")]
        extra = []
        for sec in e.get("sections") or []:
            r = len(rows)
            rows.append([Paragraph(f"<b>{esc(sec.get('section'), 120)}</b>", HEAD_CELL), "", ""])
            extra += [("BACKGROUND", (0, r), (-1, r), NAVY_2), ("SPAN", (0, r), (-1, r))]
            for row in sec.get("rows") or []:
                hit = sorted(set(row.get("checks") or []) & bad)
                res = (f'<font color="#{SEV_COLOUR["high"].hexval()[2:]}"><b>FINDING</b></font><br/>'
                       + esc(", ".join(hit), 200)) if hit else \
                      f'<font color="#{OK_GREEN.hexval()[2:]}"><b>PASS</b></font>'
                rows.append([Paragraph(esc(row.get("setting"), 160), CELL),
                             Paragraph(esc(row.get("value"), 400), CELL_SMALL),
                             Paragraph(res, CELL_SMALL)])
        story.append(_grid_table(rows, [5.6 * cm, 8.0 * cm, 3.4 * cm], zebra=False, extra=extra))
    story.append(PageBreak())
    return story


def build_control_mapping(data: dict) -> list:
    story = [_p("ISA/IEC 62443 Control Mapping", H2)]
    story.append(_p(
        f"All {len(data['catalogue'])} structured checks implemented in IACS_Monitor with their "
        "ISA/IEC 62443-3-3 Security Requirement (SR) references, foundational requirement "
        "(FR), the lowest security level (SL) at which one of the SRs applies (62443-3-3 "
        "Annex B) and checklist IDs (generated from CHECK_TYPE_REFERENCE)."
        + (f" Checks marked <b>&gt; SL-T</b> apply only above the target level SL-T "
           f"{data['target_sl']} and were not evaluated for this report."
           if data.get("target_sl") is not None else ""), BODY))
    cat_labels = {"real_time": "Real-Time Monitoring Checks", "periodic_review": "Periodic Review Checks",
                  "config_review": "Configuration Review Checks", "traffic_review": "Traffic Review Checks"}
    rows = [_heads("Check Name", "Area", "Reference", "Note", "Severity")]
    target = data.get("target_sl")
    excluded_names = set(data.get("excluded_check_names") or [])
    extra = []
    cats = list(cat_labels) + sorted({v["category"] for v in data["catalogue"].values()} - set(cat_labels))
    for cat in cats:
        items = [(k, v) for k, v in data["catalogue"].items() if v["category"] == cat]
        if not items:
            continue
        r = len(rows)
        rows.append([Paragraph(f"<b>{esc(cat_labels.get(cat, fmt_category(cat)))}</b> ({len(items)})", HEAD_CELL),
                     "", "", "", ""])
        extra += [("BACKGROUND", (0, r), (-1, r), NAVY_2), ("SPAN", (0, r), (-1, r))]
        for k, v in sorted(items, key=lambda kv: (_checklist_sort_key(kv[1]["checklist_id"]), kv[0])):
            note = " · ".join(x for x in [("above SL-T" if not _in_target(v.get("sl"), target) else ""),
                                          ("excluded" if k in excluded_names else "")] if x)
            rows.append([Paragraph(esc(fmt_check_name(k)), CELL),
                         Paragraph(esc(SECTION_NAMES.get(section_of(v["checklist_id"]), "Other")), CELL_SMALL),
                         Paragraph(esc(_primary_reference(k, v["sr"])), CELL_SMALL),
                         Paragraph(esc(note), CELL_SMALL), _sev_cell(v["severity"])])
    story.append(_grid_table(rows, [4.6 * cm, 3 * cm, 5.4 * cm, 2 * cm, 1.7 * cm],
                             zebra=False, extra=extra))
    return story


# ---------------------------------------------------------------------------
# Permitted Communication Paths & Permissive Policies (docs/access-path-review.md
# phase 4): the lines the reviewer selected in Access Review.
# ---------------------------------------------------------------------------
ACCESS_PATHS_TITLE = "Permitted Communication Paths & Permissive Policies"
# Lines printed per group (the counts in the summary table are always exact).
MAX_ACCESS_PATH_LINES_PER_GROUP = int(os.environ.get("IACS_REPORT_MAX_PATH_LINES", "200") or 200)
ACCESS_PATH_FOOTNOTE = (
    "Not seen in capture means the path was absent from the captured traffic for the "
    "stated window; it does not prove the rule is unused. Rule-hit history is the basis "
    "for unused-rule findings.")
_AP_CLASS_LABEL = {
    "it_ot_bypass": "IT/OT boundary bypass",
    "permissive": "Permissive",
    "exception": "Accepted exception",
    "reviewed_ok": "Reviewed OK",
    "unclassified": "Unclassified, for review",
}
# (key, label, shown when empty, description).  The summary table has one
# row per printed group, in this order, with the group header's label.
_AP_GROUPS = (
    ("it_ot_bypass", "IT/OT boundary bypass", True, None),
    ("permissive", "Permissive", True, None),
    ("accepted", "Accepted exception / Reviewed OK", False, None),
    ("unclassified", "Unclassified, for review", True,
     "Lines nobody has classified yet, included for review."),
    ("unexplained", "Unexplained flows", False,
     "Captured traffic that no firewall rule allows; the reviewer's classification "
     "is shown in the note column."),
)
# ISA/IEC 62443 references of a line = the mapping of the check that matches
# its classification / flags (looked up in the check catalogue).
_AP_CLASS_CHECK = {"it_ot_bypass": "rule_it_ot_bypass", "permissive": "access_path_permissive"}
# conduit_through_dmz / declared_hop are deliberately absent: they record HOW
# a composed row was built (two legs meeting on a DMZ host, or joined by an
# operator-declared gateway -> jump host hop) - the sanctioned pattern of
# check 4.1 - and carry no SR of their own; a bad composed row is condemned by
# the other flags it carries.
_AP_FLAG_CHECK = {
    "it_ot_bypass": "rule_it_ot_bypass",
    "permit_any": "config_permit_any_any_any",
    "cleartext_protocol": "rule_cleartext_protocol",
    "mgmt_protocol": "rule_mgmt_protocol",
    "ot_egress_external": "rule_ot_it_dependency",
    "internet_egress": "path_ot_internet_egress",
    "dmz_bypass": "dmz_bypass",
    "source_nat": "nat_hides_source_into_ot",
    "ot_upward_skip": "chain_ot_upward_skip",          # AU F5: was missing (no SR / checklist shown)
}
_AP_FLOW_CHECK = "session_no_permitting_rule"


def _ap_ts(value) -> str:
    """ISO timestamp -> 'YYYY-MM-DD HH:MM' (UTC)."""
    if not value:
        return "?"
    if isinstance(value, datetime):
        dt = value
    else:
        try:
            dt = datetime.fromisoformat(str(value).replace("Z", "+00:00"))
        except ValueError:
            return str(value)
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=timezone.utc)
    return dt.astimezone(timezone.utc).strftime("%Y-%m-%d %H:%M")


def _ap_window(win: Optional[dict]) -> Optional[str]:
    if not win or not (win.get("first") or win.get("last")):
        return None
    return f"{_ap_ts(win.get('first'))}–{_ap_ts(win.get('last'))}"


def access_path_traffic_text(traffic: Optional[dict], window: Optional[dict] = None) -> str:
    """The report's traffic wording (never "unused": a capture is a sample)."""
    tr = traffic or {}
    st = tr.get("status")
    if st == "seen":
        n = int(tr.get("sessions") or 0)
        return f"Seen in capture ({n} session{'' if n == 1 else 's'})"
    if st == "not_seen":
        w = _ap_window(tr.get("capture_window") or window)
        return f"Not seen in capture (window {w})" if w else "Not seen in capture"
    if st == "partial":
        return "Seen on one leg"
    return "No capture loaded"


def _ap_rule_hits(traffic: Optional[dict]) -> Optional[str]:
    tr = traffic or {}
    if tr.get("rule_hits") is None:
        return None
    s = f"Rule hits: {tr['rule_hits']}"
    if tr.get("rule_hits_since"):
        s += f" since {_ap_ts(tr['rule_hits_since'])}"
    if tr.get("last_matched"):
        s += f", last matched {_ap_ts(tr['last_matched'])}"
    return s


def _ap_srs(catalogue: dict, checks: list) -> str:
    out: list = []
    for c in checks:
        sr = (catalogue.get(c) or {}).get("sr")
        for ref in (sr or "").split(","):
            ref = ref.strip()
            if ref and ref not in out:
                out.append(ref)
    return ", ".join(out)


def _ap_line(item: dict, catalogue: dict, window: Optional[dict], kind: str) -> dict:
    from app.parsers.access_path_findings import allowed_by, path_label

    cls = item.get("classification") or "unclassified"
    flags = list(item.get("flags") or [])
    checks = []
    if kind == "unexplained":
        checks.append(_AP_FLOW_CHECK)
    if cls in _AP_CLASS_CHECK:
        checks.append(_AP_CLASS_CHECK[cls])
    checks += [_AP_FLAG_CHECK[f] for f in flags if f in _AP_FLAG_CHECK]
    if kind == "unexplained":
        port = item["server"].get("port")
        service = f"{item.get('transport') or 'ip'}/{port}" if port is not None \
            else str(item.get("transport") or "ip")
        traffic = {"status": "seen", "sessions": item.get("sessions")}
        hops = []
    else:
        legs = item.get("legs") or []
        if item.get("direction") == "composed" and len(legs) == 2:
            service = " → ".join(", ".join(leg.get("service") or []) or "any" for leg in legs)
        else:
            service = ", ".join(item.get("service") or []) or "any"
        traffic = item.get("traffic") or {}
        hops = [allowed_by({"chain": [h]}) for h in item.get("chain") or []]
    return {
        "tag_key": item.get("tag_key"), "kind": kind, "classification": cls,
        "level": (item.get("client") or item.get("src") or {}).get("level"),
        "path": path_label(item), "service": service,
        "allowed_by": hops, "flags": flags,
        "traffic_status": traffic.get("status") or "no_capture",
        "traffic": access_path_traffic_text(traffic, window),
        "rule_hits": None if kind == "unexplained" else _ap_rule_hits(traffic),
        "note": item.get("note"), "classified_by": item.get("classified_by"),
        "sr": _ap_srs(catalogue, checks),
    }


def _ap_sort_key(line: dict):
    lvl = line.get("level")
    return (-(lvl if isinstance(lvl, (int, float)) else -99), line["path"], line["service"])


_AP_HOSTS_SHOWN = 8      # addresses listed on a rolled-up line before "+N more"


def _ap_group_line(members: list, kind: str, catalogue: dict, window: Optional[dict],
                   vary: str, scopes: list) -> dict:
    """One report line for rows that differ only in the destination (or
    source) host: the fixed side as usual, the varying side as "N hosts in
    <zone>" with the addresses listed, traffic / rule hits / notes summed."""
    from app.parsers.access_path_findings import _path_sides, _scope_label, fmt_level, zone_parts_label
    first = members[0]
    base = _ap_line(first, catalogue, window, kind)
    src, dst = _path_sides(first)
    side = dst if vary == "dst" else src
    zone = zone_parts_label(side["zone_parts"]) if side.get("zone_parts") else (side.get("zone") or "")
    n = len(scopes) or len(members)
    many = f"{n} {'destinations' if vary == 'dst' else 'sources'} in {fmt_level(side.get('level'))}" \
           + (f" {zone}" if zone else "")
    mid = ""
    if first.get("pivot"):
        piv = first["pivot"]
        mid = f" → {fmt_level(piv.get('level'))} {piv.get('ip')}"
        if first.get("hop"):
            mid += f" ⇒ {first['hop'].get('to_ip')} (declared hop)"
    base["path"] = (f"{_scope_label(src)}{mid} → {many}" if vary == "dst"
                    else f"{many}{mid} → {_scope_label(dst)}")
    base["hosts"] = list(scopes[:_AP_HOSTS_SHOWN]) + (
        [f"+{len(scopes) - _AP_HOSTS_SHOWN} more"] if len(scopes) > _AP_HOSTS_SHOWN else [])
    base["members"] = len(members)
    base["vary"] = vary
    # traffic: per-status counts over the members, sessions and rule hits summed
    st = Counter()
    sessions = 0
    hits = 0
    for m in members:
        tr = m.get("traffic") or {}
        s = tr.get("status") or "no_capture"
        st[s] += 1
        sessions += int(tr.get("sessions") or 0)
        hits += int(tr.get("rule_hits") or 0)
    base["traffic_status"] = ("seen" if st["seen"] else "partial" if st["partial"]
                              else "not_seen" if st["not_seen"] else "no_capture")
    if len(st) == 1:
        only = next(iter(st))
        base["traffic"] = access_path_traffic_text({"status": only, "sessions": sessions}, window)
        if only != "seen":
            base["traffic"] = f"{base['traffic']} - all {len(members)}"
        else:
            base["traffic"] = f"Seen in capture on {st['seen']} of {len(members)} ({sessions} session{'s' if sessions != 1 else ''})"
    else:
        parts = []
        if st["seen"]:
            parts.append(f"seen on {st['seen']} ({sessions} session{'s' if sessions != 1 else ''})")
        if st["partial"]:
            parts.append(f"one leg on {st['partial']}")
        if st["not_seen"]:
            parts.append(f"not seen on {st['not_seen']}")
        if st["no_capture"]:
            parts.append(f"no capture for {st['no_capture']}")
        base["traffic"] = f"Of {len(members)}: " + ", ".join(parts)
    base["rule_hits"] = f"Rule hits: {hits}" if hits else None
    notes = []
    whos = []
    for m in members:
        if m.get("note") and m["note"] not in notes:
            notes.append(m["note"])
        if m.get("classified_by") and m["classified_by"] not in whos:
            whos.append(m["classified_by"])
    base["note"] = "; ".join(notes[:3]) + (f"; +{len(notes) - 3} more" if len(notes) > 3 else "") or None
    base["classified_by"] = ", ".join(whos[:2]) + (f" +{len(whos) - 2}" if len(whos) > 2 else "") or None
    return base


def _ap_roll_up(items: list, catalogue: dict, window: Optional[dict]) -> list:
    """Rolled report lines for one classification group: ``items`` =
    [(item, kind)]; unexplained flows stay single."""
    from app.parsers.access_path_groups import roll_up
    out = []
    paths = [(it, k) for it, k in items if k != "unexplained"]
    flows = [(it, k) for it, k in items if k == "unexplained"]
    kind_of = {id(it): k for it, k in paths}
    for g in roll_up([it for it, _k in paths]):
        rows = g["rows"]
        if g["vary"] is None or len(rows) < 2:
            out.append(_ap_line(rows[0], catalogue, window, kind_of[id(rows[0])]))
        else:
            out.append(_ap_group_line(rows, kind_of[id(rows[0])], catalogue, window, g["vary"], g["scopes"]))
    out += [_ap_line(it, catalogue, window, k) for it, k in flows]
    out.sort(key=_ap_sort_key)
    return out


def collect_access_path_section(db, site_id: int, site_name: Optional[str],
                                catalogue: dict) -> dict:
    """The report-included Access Review lines of one site (ONE enumeration).

    Lines = rows / composed conduits / unexplained flows whose effective
    report_include is true; intra-zone rows (hidden in the review screen by
    default) only when the reviewer explicitly included them."""
    from app.models import Firewall
    from app.parsers.access_paths import _enumerate, report_lines
    from app.parsers.site_scope import analysis_site

    sec = {"site": site_name, "site_id": site_id, "error": None, "uploads": [],
           "capture_window": None, "groups": {g[0]: [] for g in _AP_GROUPS},
           "summary": [], "orphaned": [], "included": 0, "truncated": False}
    try:
        uploads = db.query(Firewall.name, Firewall.config_uploaded_at) \
                    .filter(Firewall.site_id == site_id).order_by(Firewall.name).all()
        sec["uploads"] = [(n, at) for n, at in uploads]
        with analysis_site(db, site_id):
            res = _enumerate(db, overlay=True, unmatched_cap=0)
        window = res["unmatched"].get("capture_window")
        sec["capture_window"] = window if _ap_window(window) else None
        sec["truncated"] = bool(res["truncated"])
        sec["unplaced_firewalls"] = list(res.get("unplaced_firewalls") or [])     # MP-03
        # the same selection GET /access-paths counts as counts.report_include
        selected = report_lines(res)
        lines = [_ap_line(item, catalogue, window, kind) for item, kind in selected]
        lines.sort(key=_ap_sort_key)
        items_by_group: dict = {g[0]: [] for g in _AP_GROUPS}

        def _grp(kind, cls):
            if kind == "unexplained":
                return "unexplained"
            if cls in ("exception", "reviewed_ok"):
                return "accepted"
            return cls

        for ln in lines:
            sec["groups"][_grp(ln["kind"], ln["classification"])].append(ln)
        for item, kind in selected:
            items_by_group[_grp(kind, item.get("classification") or "unclassified")].append((item, kind))
        sec["included"] = len(lines)
        # roll-up: one printed line per set of rows that differ only in the
        # destination (or source) host; the counts above stay per path
        sec["rolled"] = {}
        for g, its in items_by_group.items():
            by_cls: dict = {}
            for it, k in its:            # never mix classifications on one line
                by_cls.setdefault(it.get("classification") or "unclassified", []).append((it, k))
            rolled = []
            for cls_items in by_cls.values():
                rolled += _ap_roll_up(cls_items, catalogue, window)
            rolled.sort(key=_ap_sort_key)
            sec["rolled"][g] = rolled
        sec["printed"] = sum(len(v) for v in sec["rolled"].values())
        # one summary row per printed group (same order, label and count as
        # the group headers)
        for key, label, always, _desc in _AP_GROUPS:
            sel = sec["groups"][key]
            if not sel and not always:
                continue
            st = Counter(ln["traffic_status"] for ln in sel)
            sec["summary"].append({
                "group": key, "label": label, "lines": len(sel),
                "seen": st["seen"] + st["partial"], "partial": st["partial"],
                "not_seen": st["not_seen"], "no_capture": st["no_capture"]})
        sec["orphaned"] = [t for t in res["orphaned"]
                           if t.get("classification") != "unclassified" or t.get("note")]
    except Exception:  # never lose the whole report over this section
        log.exception("access-path report section failed for site %s", site_id)
        try:
            db.rollback()
        except Exception:  # pragma: no cover
            pass
        sec["error"] = "The permitted-path section could not be computed; see the server log."
    return sec


def collect_access_path_sections(db, site_id: Optional[int], catalogue: dict) -> list:
    """One section per site: the requested site, or every site when the
    report is not site-scoped."""
    from app.models import Site
    try:
        q = db.query(Site.id, Site.name).order_by(Site.id)
        if site_id is not None:
            q = q.filter(Site.id == site_id)
        sites = q.all()
    except Exception:  # pragma: no cover - pre-multi-site schema
        db.rollback()
        return []
    return [collect_access_path_section(db, sid, name, catalogue) for sid, name in sites]


def _ap_uploads_text(uploads: list) -> str:
    if not uploads:
        return "no firewall configuration uploaded"
    parts = [f"{n}, uploaded {_ap_ts(at)} UTC" if at else f"{n}" for n, at in uploads[:12]]
    if len(uploads) > 12:
        parts.append(f"+{len(uploads) - 12} more")
    return "; ".join(parts)


# Access-path line table.  Columns are sized so no header ever wraps, and
# cell text is pre-broken by _ap_cell: a word wider than its column breaks
# only after "_", "-", "–" or "/" (never inside a word), so ReportLab's own
# long-word splitting is switched off (splitLongWords=0).
_AP_PAD = 4
_AP_COLS = (   # (header, width)
    ("Path", 2.9 * cm), ("Service", 1.45 * cm), ("Allowed by", 2.6 * cm),
    ("Flags", 2.45 * cm), ("Traffic", 2.55 * cm), ("Reviewer note", 2.55 * cm),
    ("ISA/IEC 62443", 2.5 * cm),
)
AP_CELL = _style("Normal", fontName="Helvetica", fontSize=8, leading=10.5, splitLongWords=0)
AP_CELL_SMALL = _style("Normal", fontName="Helvetica", fontSize=7.2, leading=9.2,
                       textColor=DARK_GREY, splitLongWords=0)
_AP_BREAK_SEG = re.compile(r"[^_\-–/]*[_\-–/]|[^_\-–/]+")


def _ap_cell(value: Any, style, width: float, limit: Optional[int] = 400) -> str:
    """esc()'d markup of ``value`` for a cell ``width`` wide (padding
    included) in ``style``: words that do not fit get an explicit line break
    after "_", "-", "–" or "/" (greedy); a single piece still too wide (none
    in practice) is cut by characters as a last resort."""
    if value is None:
        return ""
    s = value if isinstance(value, str) else str(value)
    s = _CTRL_RE.sub(" ", s)
    if limit is not None and len(s) > limit:
        s = s[: max(0, limit - 1)] + "…"
    avail = width - 2 * _AP_PAD - 1
    font, size = style.fontName, style.fontSize

    def fits(t):
        return stringWidth(t, font, size) <= avail

    out = []
    for tok in re.split(r"(\s+)", s):
        if not tok:
            continue
        if tok.isspace() or fits(tok):
            out.append(esc(tok, None))
            continue
        lines, cur = [], ""
        for seg in _AP_BREAK_SEG.findall(tok):
            if fits(cur + seg):
                cur += seg
                continue
            if cur:
                lines.append(cur)
            cur = ""
            while not fits(seg):          # last resort: a piece wider than the column
                n = len(seg) - 1
                while n > 1 and not fits(seg[:n]):
                    n -= 1
                lines.append(seg[:n])
                seg = seg[n:]
            cur = seg
        if cur:
            lines.append(cur)
        out.append("<br/>".join(esc(x, None) for x in lines))
    return "".join(out)


def _ap_group_table(lines: list, group: str, no_firewall: bool = False) -> list:
    widths = [w for _h, w in _AP_COLS]
    W = dict(_AP_COLS)
    rows = [_heads(*(h for h, _w in _AP_COLS))]
    for ln in lines[:MAX_ACCESS_PATH_LINES_PER_GROUP]:
        path = _ap_cell(ln["path"], AP_CELL, W["Path"], 300)
        if ln.get("hosts"):
            path += ('<br/><font color="#555555">'
                     + _ap_cell(", ".join(ln["hosts"]), AP_CELL_SMALL, W["Path"], 300) + "</font>")
        if ln["kind"] == "unexplained":
            # FO-08: with no firewall loaded there is no rule to miss
            why = "no firewall data loaded" if no_firewall else "no rule allows this"
            path += f' <font color="#8A2214">({why})</font>'
            allowed = why[0].upper() + why[1:]
        else:
            allowed = "<br/>".join(_ap_cell(h, AP_CELL_SMALL, W["Allowed by"], 120)
                                   for h in ln["allowed_by"]) or "—"
        traffic = _ap_cell(ln["traffic"], AP_CELL_SMALL, W["Traffic"])
        if ln["rule_hits"]:
            traffic += ("<br/>" + '<font color="#555555">'
                        f'{_ap_cell(ln["rule_hits"], AP_CELL_SMALL, W["Traffic"])}</font>')
        note = _ap_cell(ln["note"], AP_CELL_SMALL, W["Reviewer note"])
        if group in ("accepted", "unexplained") and ln["classification"] != "unclassified":
            note = f"<b>{esc(_AP_CLASS_LABEL[ln['classification']])}:</b> " + (note or "—")
        if ln["classified_by"]:
            note = ((note or "—") + '<br/><font color="#555555">— '
                    f'{_ap_cell(ln["classified_by"], AP_CELL_SMALL, W["Reviewer note"], 80)}</font>')
        # one flag per line; each ISA/IEC 62443 reference kept on one line
        flags = "<br/>".join(_ap_cell(f, AP_CELL_SMALL, W["Flags"]) for f in ln["flags"]) or "—"
        srs = ", ".join(esc(r.strip(), None).replace(" ", "\xa0")
                        for r in (ln["sr"] or "").split(",") if r.strip()) or "—"
        rows.append([
            Paragraph(path, AP_CELL),
            Paragraph(_ap_cell(ln["service"], AP_CELL_SMALL, W["Service"], 120), AP_CELL_SMALL),
            Paragraph(allowed if ln["kind"] != "unexplained" else esc(allowed), AP_CELL_SMALL),
            Paragraph(flags, AP_CELL_SMALL),
            Paragraph(traffic, AP_CELL_SMALL),
            Paragraph(note or "—", AP_CELL_SMALL),
            Paragraph(srs, AP_CELL_SMALL),
        ])
    out = [_grid_table(rows, widths, extra=[("LEFTPADDING", (0, 0), (-1, -1), _AP_PAD),
                                            ("RIGHTPADDING", (0, 0), (-1, -1), _AP_PAD)])]
    if len(lines) > MAX_ACCESS_PATH_LINES_PER_GROUP:
        out.append(_p(f"<i>… {len(lines) - MAX_ACCESS_PATH_LINES_PER_GROUP} more line(s) in "
                      "this group not listed.</i>", SMALL))
    return out


def build_access_path_section(sec: dict, title: str = ACCESS_PATHS_TITLE) -> list:
    story = [_p(esc(title), H2)]
    if sec.get("error"):
        story.append(_p(esc(sec["error"]), BODY))
        return story
    if not sec["included"]:
        story.append(_p("No lines were selected for this report in Access Review.", BODY))
    else:
        win = _ap_window(sec.get("capture_window"))
        capture = (f"checked against captured traffic (capture window {win} UTC)" if win else
                   "not checked against traffic: no packet capture is loaded for this site")
        n = sec["included"]
        printed = sec.get("printed", n)
        story.append(_p(
            "Paths allowed by firewall rules between Purdue levels, built from the firewall "
            f"configuration ({esc(_ap_uploads_text(sec['uploads']), 900)}) and {esc(capture)}. "
            f"This section lists the <b>{n}</b> line{'s' if n != 1 else ''} the reviewer selected "
            "for reporting in Access Review, grouped by classification."
            + (f" Lines that differ only in the destination or source host are rolled into one "
               f"({printed} printed); each lists its hosts." if printed < n else ""), BODY))
        if sec.get("truncated"):
            story.append(_p("<i>The path enumeration reached its row budget; some paths may be "
                            "missing.</i>", SMALL))
        unp = sec.get("unplaced_firewalls") or []
        if unp:
            story.append(_p(
                "<b>Not in the model:</b> " + esc("; ".join(
                    f"{u.get('firewall') or '#' + str(u.get('firewall_id'))} ({u.get('rule_count', 0)} rules; "
                    f"{u.get('reason', '')})" for u in unp), 900)
                + ". No listed path passes through these firewalls, so this list is incomplete "
                  "wherever they sit and a crossing they deny may appear as allowed. Label at "
                  "least two of their interfaces and re-run.", SMALL))
        rows = [_heads("Classification", "Lines", "Seen in capture", "Not seen in capture",
                       "No capture")]
        tot = Counter()
        for r in sec["summary"]:
            for k in ("lines", "seen", "not_seen", "no_capture", "partial"):
                tot[k] += r[k]
            rows.append([Paragraph(esc(r["label"]), CELL)]
                        + [Paragraph(str(r[k]), CELL) for k in ("lines", "seen", "not_seen",
                                                                 "no_capture")])
        rows.append([Paragraph("Total", CELL_BOLD)]
                    + [Paragraph(str(tot[k]), CELL_BOLD) for k in ("lines", "seen", "not_seen",
                                                                    "no_capture")])
        story.append(_grid_table(rows, [5.2 * cm, 2 * cm, 3.2 * cm, 3.6 * cm, 3 * cm],
                                 extra=[("BACKGROUND", (0, -1), (-1, -1), TOTAL_BG)]))
        if tot["partial"]:
            story.append(_p(f"Seen in capture includes {tot['partial']} composed line(s) seen "
                            "on one leg only.", SMALL))
        for key, header, always, desc in _AP_GROUPS:
            lines = sec["groups"][key]
            if not lines and not always:
                continue
            rolled = (sec.get("rolled") or {}).get(key)
            if rolled is None:
                rolled = lines
            head = [_p(esc(f"{header} ({len(lines)})"
                           + (f" · {len(rolled)} lines" if len(rolled) < len(lines) else "")), H3)]
            if desc:
                head.append(_p(esc(desc), SMALL))
            if not lines:
                story.append(KeepTogether(head + [_p("<i>No lines in this group.</i>", SMALL)]))
                continue
            # Keep the group heading on the same page as the start of its table.
            body = _ap_group_table(rolled, key, no_firewall=not sec.get("uploads"))
            story.append(KeepTogether(head + body[:1]))
            story += body[1:]
        story.append(_sp(0.2))
        story.append(_p(esc(ACCESS_PATH_FOOTNOTE), SMALL))
        story.append(_p("ISA/IEC 62443 references for each line come from the mapping of the "
                        "check that matches its classification and flags.", SMALL))
        story.append(_p("Flags: it_ot_bypass = IT side (L3 and up, incl. the DMZ) reaches L0/L1, or "
                        "L4/L5 reaches L2, in one routed session; ot_egress_external = OT zone "
                        "opens connections to IT / external; ot_upward_skip = L0/L1 to L3 and up, or "
                        "L2 to L4/L5, in one routed session (the upward mirror of it_ot_bypass); permit_any = any source / destination / service; "
                        "cleartext_protocol = cleartext protocol (FTP, Telnet, HTTP, SNMP v1/v2c...) across a boundary; "
                        "mgmt_protocol = management protocol (SSH, Telnet, RDP, VNC, SNMP, WinRM...) across a boundary; "
                        "industrial_proto_out_of_zone = industrial protocol outside its zone; "
                        "direction_unverified = no Purdue level behind the policy, the row may be "
                        "reversed (label the firewall interfaces); "
                        "internet_egress = an OT zone (site operations, L3, included) can open "
                        "sessions to the internet; dmz_bypass = the site has a DMZ, yet IT / "
                        "internet / remote users (L4-L5) and site operations (L3) are joined "
                        "directly; "
                        "conduit_through_dmz / declared_hop (informational) = two legs joined on a "
                        "DMZ host, the latter through an operator-declared gateway "
                        "⇒ jump host step that no firewall sees; pivot_outside_dmz = two legs "
                        "joined on a host that is NOT in the DMZ (e.g. an RDP session host at L3); "
                        "nat_published = a firewall VIP publishes the destination; source_nat = "
                        "a firewall translates the source on the way (the OT side cannot see who "
                        "connected).", SMALL))
    orphaned = sec.get("orphaned") or []
    if orphaned:
        story.append(_p("Classifications whose path is no longer in the configuration", H3))
        rows = [_heads("Classification", "Recorded policy", "Reviewer note", "Classified")]
        for t in orphaned[:MAX_ACCESS_PATH_LINES_PER_GROUP]:
            pol = (f"policy {t['policy_id']}" if t.get("policy_id") else
                   ("unexplained flow" if t.get("kind") == "unexplained" else "—"))
            if t.get("vdom"):
                pol += f" (vdom {t['vdom']})"
            who = " ".join(x for x in (t.get("classified_by") or "",
                                       _ap_ts(t["classified_at"]) if t.get("classified_at") else "")
                           if x)
            rows.append([Paragraph(esc(_AP_CLASS_LABEL.get(t.get("classification"),
                                                           t.get("classification"))), CELL),
                         Paragraph(esc(pol, 120), CELL_SMALL),
                         Paragraph(esc(t.get("note"), 300) or "—", CELL_SMALL),
                         Paragraph(esc(who, 160) or "—", CELL_SMALL)])
        story.append(_grid_table(rows, [3.8 * cm, 4 * cm, 6 * cm, 3.2 * cm]))
    return story


def build_access_paths(data: dict) -> list:
    """The section for the report's site (or one per site when the report
    is not site-scoped and several sites exist)."""
    secs = data.get("access_paths")
    if not secs:
        return []
    story = []
    for sec in secs:
        title = ACCESS_PATHS_TITLE
        if len(secs) > 1 and sec.get("site"):
            title += f" — {sec['site']}"
        story += build_access_path_section(sec, title)
    story.append(PageBreak())
    return story


def collect_rollup_data(db, *, baseline: Optional[str] = None, include_closed: bool = False,
                        site: Optional[str] = None, target_sl: Optional[int] = None,
                        now: Optional[datetime] = None, include_zones: bool = True,
                        apply_check_selection: bool = True) -> dict:
    """Explicit ALL-SITES roll-up (multi-site phase 2): one complete
    per-site data set (collect_report_data with that site_id) per site.
    Sites are isolated, so nothing is merged across them - the PDF lists one
    section per site.  ``baseline``: name looked up in each site; a site
    without it reports its active baseline."""
    from app.models import Site
    now = now or datetime.now(timezone.utc)
    per_site = []
    for s_id, s_name in db.query(Site.id, Site.name).order_by(Site.id).all():
        try:
            d = collect_report_data(db, baseline=baseline, include_closed=include_closed,
                                    site=s_name, site_id=s_id, target_sl=target_sl, now=now,
                                    include_zones=include_zones, apply_check_selection=apply_check_selection)
        except LookupError:
            d = collect_report_data(db, include_closed=include_closed,
                                    site=s_name, site_id=s_id, target_sl=target_sl, now=now,
                                    include_zones=include_zones, apply_check_selection=apply_check_selection)
        per_site.append(d)
    label = site or f"All sites (roll-up of {len(per_site)})"
    statuses = STATUSES if include_closed else ["open", "acknowledged"]
    return {
        "rollup": True, "generated_at": now, "site": label, "site_id": None,
        "target_sl": target_sl,
        "statuses": statuses, "include_closed": include_closed, "baseline": None,
        "findings": [f for d in per_site for f in d["findings"]],
        "false_positives": [f for d in per_site for f in d.get("false_positives") or []],
        "catalogue": per_site[0]["catalogue"] if per_site else check_catalogue(),
        "sites": per_site,
    }


def build_rollup_story(data: dict, layout: str = "lrqa") -> list:
    """Cover + one section per site (summary, findings, attestation,
    firewall inventory, coverage) + the control mapping once."""
    story = (build_cover_public(data) if layout == "public" else build_cover(data) + build_contents(data))
    story.append(_p("1&nbsp;&nbsp;Sites in this report", H1))
    rows = [_heads("Site", "Findings in scope", "Audit baseline", "Firewall devices")]
    for d in data["sites"]:
        b = d.get("baseline")
        rows.append([Paragraph(esc(d["site"]), CELL), Paragraph(str(len(d["findings"])), CELL),
                     Paragraph(esc(b["name"] if b else "(none)"), CELL),
                     Paragraph(str(len(d["firewall_devices"])), CELL)])
    story.append(_grid_table(rows, [5.5 * cm, 3.5 * cm, 4.5 * cm, 3 * cm]))
    story.append(_p("Sites are analysed in isolation; each site below has its own findings, "
                    "attestations and firewall inventory.", BODY))
    story.append(PageBreak())
    for i, d in enumerate(data["sites"], 2):
        story.append(_p(f"{i}&nbsp;&nbsp;Site: {esc(d['site'])}", H1))
        story += build_executive_summary(d)
        story += build_findings_summary(d, num=f"{i}.1", analysis_num=f"{i}.2")
        story += build_findings(d, num=f"{i}.2")
        story += build_false_positives(d)
        story += build_closed_findings(d)
        story += build_excluded_checks(d)
        story += build_attestation(d)
        story += build_zones(d)
        story += build_firewall_inventory(d)
        story += build_shadow_rules(d)
        story += build_access_paths(d)
        story += build_coverage(d)
    story += build_appendix_intro(num=str(len(data["sites"]) + 2))
    story += build_control_mapping(data)
    story += build_standards()
    return story


def build_appendix_intro(num: str = "6") -> list:
    story = [_p(f"{esc(num)}&nbsp;&nbsp;Appendix", H1), _p("Finding Severity Methodology", H2),
             _p("IACS_Monitor assigns each check a default severity from the OT firewall review checklist and the IEC 62443 "
                "requirement it maps to, then adjusts it from the evidence: the Purdue levels of the two sides of a rule or flow, "
                "whether the path leads into the control zones (L0-L2), whether a cleartext or management protocol is involved, "
                "and whether the operator has documented a conduit or approval. The recorded severity and its reason are shown "
                "on each finding in the console.", BODY)]
    rows = [_heads("Severity", "Meaning")]
    for sv, txt in (("critical", "Direct exposure of control equipment (L0-L2) or of the firewall itself; act now."),
                    ("high", "A boundary or access-control requirement is not met on a path into OT."),
                    ("medium", "A hardening or monitoring requirement is not met; exploitable with a further step."),
                    ("low", "Deviation from best practice with limited exposure."),
                    ("info", "For awareness; no action required by the standard.")):
        rows.append([Paragraph(f'<font color="#{SEV_COLOUR[sv].hexval()[2:]}">{sv.title()}</font>', CELL), Paragraph(txt, CELL)])
    story.append(_grid_table(rows, [3 * cm, 14 * cm], zebra=False))
    story.append(_sp(0.4))
    return story


def build_standards() -> list:
    return [_p("Standards and References", H2)] + [_p("•&nbsp;&nbsp;" + esc(x), BODY) for x in (
        "ISA/IEC 62443-3-3 System security requirements and security levels",
        "ISA/IEC 62443-2-1 Security program requirements for IACS asset owners",
        "ISA/IEC 62443-3-2 Security risk assessment for system design (zones and conduits)",
        "NIST SP 800-82r3 Guide to Operational Technology Security",
        "CIS Fortinet FortiGate Benchmark")]


def build_story(data: dict) -> list:
    """Full reportlab story for ``data`` (from collect_report_data or
    collect_rollup_data).  Owner 2026-10-18: the sample report's layout -
    cover, contents, distribution list, revision history, engagement
    particulars, findings summary, analysis, appendix."""
    if data.get("rollup"):
        return build_rollup_story(data)
    story = []
    story += build_cover(data)
    story += build_contents(data)
    story += build_distribution(data)
    story += build_revisions(data)
    story += build_particulars(data)              # ends with the executive detail's own page break
    story += build_findings_summary(data)
    story += build_findings(data)
    story += build_appendix_intro()
    story += build_false_positives(data)
    story += build_closed_findings(data)
    story += build_excluded_checks(data)
    story += build_attestation(data)
    story += build_zones(data)
    story += build_firewall_inventory(data)
    story += build_shadow_rules(data)
    story += build_access_paths(data)
    story += build_coverage(data)
    story += build_config_evidence(data)
    story += build_control_mapping(data)
    story += build_standards()
    return story


def render_pdf(data: dict, out, layout: str = "lrqa") -> None:
    """Render to ``out`` (a path or a binary file-like object).  ``layout``:
    "lrqa" (the LRQA compliance report - the template, owner 2026-10-18) or
    "public" (the public compliance report: cover table, executive summary,
    findings by area)."""
    if layout not in LAYOUTS:
        raise ValueError(f"unknown report layout {layout!r}; use one of {', '.join(LAYOUTS)}")
    cov = _cover_fields(data)
    _RENDER_LOCK.acquire()               # audit 2026-10-18: _set_layout mutates module-level styles
    _set_layout(layout)
    try:
        if layout == "public":
            doc = BaseDocTemplate(out, pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN, topMargin=MARGIN, bottomMargin=MARGIN,
                                  title="OT Firewall Security Review — ISA/IEC 62443 Compliance Report",
                                  author="IACS_Monitor", subject="ISA/IEC 62443 Compliance Assessment")
            doc._iasc_site = data.get("site")
            _build_templates(doc, "public")
            doc.build(build_story_public(data))
            return
        doc = _ReportDoc(
            out, pagesize=A4, leftMargin=MARGIN, rightMargin=MARGIN, topMargin=MARGIN,
            bottomMargin=MARGIN,
            title="LRQA Compliance Report — IEC 62443 Firewall Audit",
            author=cov["author"], subject="ISA/IEC 62443 Compliance Assessment",
        )
        doc._iasc_site = data.get("site")
        doc._iasc_cover = cov
        _build_templates(doc)
        doc.multiBuild(build_story(data))
    finally:
        _set_layout("lrqa")
        _RENDER_LOCK.release()


def generate_report_bytes(db, all_sites: bool = False, layout: str = "lrqa", **opts) -> bytes:
    """Collect + render to PDF bytes (used by GET /reports/compliance.pdf).
    ``all_sites=True``: the explicit per-site roll-up (collect_rollup_data).
    ``layout``: lrqa (the LRQA compliance report) or public (the public compliance report)."""
    buf = io.BytesIO()
    if all_sites:
        opts.pop("site_id", None)
        data = collect_rollup_data(db, **opts)
    else:
        data = collect_report_data(db, **opts)
    render_pdf(data, buf, layout)
    return buf.getvalue()


# ---------------------------------------------------------------------------
# Database access for the CLI (read-only)
# ---------------------------------------------------------------------------
def open_readonly_session(url: str):
    """Session on ``url``.  SQLite files are opened with mode=ro so the report
    can never modify (or create) the database; other backends are only read."""
    from sqlalchemy import create_engine
    from sqlalchemy.engine import make_url
    from sqlalchemy.orm import sessionmaker

    u = make_url(url)
    if u.get_backend_name() == "sqlite":
        dbfile = u.database
        if not dbfile or dbfile == ":memory:" or dbfile.startswith("file:"):
            raise SystemExit(f"error: unsupported SQLite URL for a report: {url}")
        path = Path(dbfile).expanduser().resolve()
        if not path.is_file():
            raise SystemExit(f"error: database file not found: {path}")
        import sqlite3
        from urllib.parse import quote

        def _connect():
            return sqlite3.connect(f"file:{quote(str(path))}?mode=ro", uri=True,
                                   check_same_thread=False)

        engine = create_engine("sqlite://", creator=_connect)
    else:
        engine = create_engine(url)
    return sessionmaker(bind=engine, autoflush=False)(), engine


def main(argv: Optional[Iterable[str]] = None) -> int:
    ap = argparse.ArgumentParser(description="Generate the ISA/IEC 62443 compliance PDF from the IACS_Monitor DB.")
    ap.add_argument("--db", help="SQLAlchemy URL (default: $IACS_DATABASE_URL, else sqlite:///./iasc_monitor.db)")
    ap.add_argument("--out", default=DEFAULT_OUT, help=f"output PDF path (default {DEFAULT_OUT})")
    ap.add_argument("--baseline", help="baseline name for attestation scope (default: active baseline)")
    ap.add_argument("--include-closed", action="store_true", help="include closed findings")
    ap.add_argument("--site", help="site name printed on the cover and footer")
    ap.add_argument("--site-id", type=int, help="only report data of this site id")
    ap.add_argument("--all-sites", action="store_true",
                    help="roll-up report with one section per site (sites are isolated)")
    ap.add_argument("--target-sl", type=int, choices=(0, 1, 2, 3, 4),
                    help="ISA/IEC 62443 target security level: leave out checks and findings "
                         "whose 62443-3-3 requirements apply only above it")
    ap.add_argument("--all-checks", action="store_true",
                    help="ignore the site's check selection (Reports page): report every check")
    ap.add_argument("--layout", choices=LAYOUTS, default="lrqa",
                    help="lrqa = the LRQA compliance report (cover, contents, distribution list, analysis); public = the "
                         "public compliance report (cover table, executive summary, findings by area)")
    ap.add_argument("--no-zones", action="store_true",
                    help="leave out the IEC 62443-3-2 Zones and Conduits section and the zone "
                         "SL-T judgement of device findings")
    args = ap.parse_args(list(argv) if argv is not None else None)

    url = args.db or os.environ.get("IACS_DATABASE_URL") or "sqlite:///./iasc_monitor.db"
    db, engine = open_readonly_session(url)
    try:
        try:
            if not args.all_sites and args.site_id is None:
                # AU full review F8: sites are isolated - a report that silently
                # merged two sites' findings into one document was wrong for
                # both of them.  Name the site or ask for the roll-up.
                from app.models import Site
                sites = db.query(Site.id, Site.name).order_by(Site.id).all()
                if len(sites) > 1:
                    print("error: this database has %d sites (%s); pass --site-id N for one site "
                          "or --all-sites for the roll-up" % (
                              len(sites), ", ".join(f"{i}={n}" for i, n in sites)), file=sys.stderr)
                    return 2
            if args.all_sites:
                data = collect_rollup_data(db, baseline=args.baseline,
                                           include_closed=args.include_closed, site=args.site,
                                           target_sl=args.target_sl, include_zones=not args.no_zones,
                                           apply_check_selection=not args.all_checks)
            else:
                data = collect_report_data(db, baseline=args.baseline,
                                           include_closed=args.include_closed, site=args.site,
                                           site_id=args.site_id, target_sl=args.target_sl,
                                           include_zones=not args.no_zones,
                                           apply_check_selection=not args.all_checks)
        except LookupError as exc:
            print(f"error: {exc}", file=sys.stderr)
            return 2
    finally:
        db.close()
        engine.dispose()
    render_pdf(data, args.out, args.layout)
    print(f"Report written to: {args.out} ({len(data['findings'])} findings, "
          f"{len(data['catalogue'])} checks)")
    return 0


if __name__ == "__main__":
    sys.exit(main())
