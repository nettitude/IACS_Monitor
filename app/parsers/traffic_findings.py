"""
Traffic-derived 62443 findings.

Distinct from forti_config_parser.py's config-level checks: this module
evaluates already-ingested NetworkSession/ProtocolDetail data (from
pcap_parser.py) against ApprovedHost baseline data, rather than parsing
a config file fresh. Findings from here use category="periodic_review" -
section 8 of the OT Firewall Review 62443 Checklist ("PCAP / ARP
Validation") is fundamentally a review-cycle activity (you assess a
captured pcap after the fact), not a real-time alert in this project's
current architecture - there's no live/streaming capture ingest, only
batch pcap upload (see pcap_parser.py).
"""
import hashlib
import ipaddress
from datetime import datetime, timezone
from typing import Optional

from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session as DBSession, joinedload

from app.models import ACTIVE_FINDING_STATUSES, ApprovedHost, Baseline, Finding, Host, NetworkSession, ProtocolDetail
from app.parsers.common import normalize_mac
from app.parsers.site_scope import current_site, scope_module

# Protocols whose analyzers report an "operation" field distinguishing
# read from write - verified directly against each analyzer's actual
# code before relying on it (all four consistently set "operation" at
# the top level of the dict that becomes ProtocolDetail.fields).
# PROFINET is deliberately excluded: its cyclic RT I/O writes aren't
# decoded at the operation level at all - profinet_analyzer.py's own
# docstring explains why that's a genuine protocol limitation (the
# data's meaning is defined by project-specific engineering files not
# visible on the wire), not an oversight here. Silently treating
# PROFINET as "no writes found" would be worse than being explicit
# about not covering it.
_WRITE_CAPABLE_PROTOCOLS = ("modbus", "dnp3", "s7comm", "ethernet_ip", "profinet")   # IO-06: DCP Set


# Operations that change process state or program content. "write" is the
# classic data write; "program" (S7 block download/upload) and "control"
# (S7 PLC STOP / PLC control, DNP3 cold/warm restart, initialize, start/
# stop application) are high-impact operations the analyzers classify
# explicitly so they never fall into "other" (T3-33).
_FLAGGED_OPERATIONS = frozenset({"write", "program", "control"})
_HIGH_IMPACT_OPERATIONS = frozenset({"program", "control"})

# Well-known server port per protocol - the side that is NOT on this port
# is the client (the only side whose requests count).
_SERVER_PORTS = {"modbus": 502, "s7comm": 102, "dnp3": 20000, "ethernet_ip": 44818}

_MAX_DETAIL_IDS_IN_EVIDENCE = 20


def _get_approved_engineering_hosts(db: DBSession) -> tuple:
    """
    Resolve ApprovedHost rows (role in engineering_ws/hmi, under the
    currently active Baseline) into (networks, macs): ip values become
    ipaddress network objects (a bare IP becomes a /32; a CIDR is used
    as-is) and mac values are normalized. Entries with only a MAC are
    matched by MAC (T3-33). Malformed entries are skipped rather than
    raising, since one bad row in baseline data shouldn't take down the
    whole check.
    """
    networks = []
    macs = set()
    query = (
        db.query(ApprovedHost)
        .join(Baseline, ApprovedHost.baseline_id == Baseline.id)
        .filter(Baseline.is_active.is_(True), ApprovedHost.role.in_(("engineering_ws", "hmi")))
    )
    for host in query.all():
        if host.mac:
            mac = normalize_mac(host.mac)
            if mac:
                macs.add(mac)
        if not host.ip:
            continue
        try:
            networks.append(ipaddress.ip_network(host.ip, strict=False))
        except ValueError:
            continue
    # Declared engineering sources (engineering networks / VLANs / trusted
    # engineering workstations - app.parsers.mgmt_networks).
    from app.parsers.mgmt_networks import PURPOSE_ENG, build_context
    ctx = build_context(db)
    networks += [n for n, d, p in ctx.nets if p == PURPOSE_ENG and not d.startswith("baseline ")]
    for ip, (_d, p) in ctx.host_ips.items():
        if p == PURPOSE_ENG:
            try:
                networks.append(ipaddress.ip_network(ip, strict=False))
            except ValueError:
                pass
    return networks, macs


def _get_approved_engineering_networks(db: DBSession) -> list:
    """Backwards-compatible wrapper: IP networks only."""
    return _get_approved_engineering_hosts(db)[0]


def _host_is_approved(ip: Optional[str], approved_networks: list,
                      mac: Optional[str] = None, approved_macs: Optional[set] = None) -> bool:
    if mac and approved_macs:
        if normalize_mac(mac) in approved_macs:
            return True
    if not ip or not approved_networks:
        return False
    try:
        addr = ipaddress.ip_address(ip)
    except ValueError:
        return False
    return any(addr in net for net in approved_networks)


def _is_request(detail: ProtocolDetail) -> bool:
    fields = detail.fields if isinstance(detail.fields, dict) else {}
    direction = detail.direction or fields.get("direction")
    return direction != "response"


def _client_server(session: NetworkSession, protocol: str) -> tuple:
    """
    (client_host, server_host) for a session. NetworkSession rows are
    bidirectional and src/dst reflect whichever packet came first, so the
    client is inferred from the protocol's well-known server port.
    """
    server_port = _SERVER_PORTS.get(protocol)
    if server_port is not None:
        if session.src_port == server_port and session.dst_port != server_port:
            return session.dst_host, session.src_host
    return session.src_host, session.dst_host


# C-01: ports we treat as the server side even when numerically higher than
# the peer. The lower-numbered port already wins the common OT cases (502 vs an
# ephemeral 5xxxx), so this is only a defensive override; it reuses the
# protocol server ports this module already knows.
_KNOWN_SERVER_PORTS = frozenset(_SERVER_PORTS.values())

# Below this, a port is "privileged" and almost always a listening service,
# never an ephemeral client port. Used only to decide which side is the server
# when the peer has no port at all (otherwise the lower-port rule decides).
_PRIVILEGED_PORT_MAX = 1024


def _is_server_port(p) -> bool:
    """A port that positively identifies the server side: a known OT service
    port, or a privileged (<1024) port. An ephemeral high port does NOT, so a
    lone ephemeral port never masquerades as a server."""
    return isinstance(p, int) and (p in _KNOWN_SERVER_PORTS or p < _PRIVILEGED_PORT_MAX)


def canonical_flow(src_endpoint, src_port, dst_endpoint, dst_port):
    """C-01: map a bidirectional session's endpoints to a stable
    ``(client, server, server_port)`` triple, independent of which packet was
    captured first.

    A NetworkSession's src/dst reflect whichever packet the capture saw first
    (pcap_parser's intentional bidirectional model), so one logical flow -
    e.g. an IT client talking to an OT server on :502 - can appear in either
    orientation and with a different ephemeral client port each time it is
    captured. Keying a finding on the raw orientation therefore splits one
    flow into several findings and lets none of them match the real-time FAZ
    finding (which is keyed on the server port). Canonicalising first gives
    pcap and FAZ findings for one logical flow a shared identity.

    The server is the side on the well-known service port: a recognised service
    port if exactly one side carries one, otherwise the lower-numbered port
    (ephemeral client ports are high). ``endpoint`` values are opaque (a Host,
    an IP string, ...) - only the ports decide orientation. Consistent with
    ``_client_server`` (which does the same using a protocol's server port).
    """
    sp = src_port if isinstance(src_port, int) else None
    dp = dst_port if isinstance(dst_port, int) else None
    src_server = _is_server_port(sp)
    dst_server = _is_server_port(dp)
    if src_server and not dst_server:
        server_is_src = True
    elif dst_server and not src_server:
        server_is_src = False
    elif sp is not None and dp is not None:
        # Both or neither are recognised service ports: the lower-numbered port
        # is the server (ephemeral client ports are high). Catches reversed
        # captures of registered-port services too (e.g. 1433 vs 50001).
        server_is_src = sp < dp
    elif sp is not None and dp is None:
        # Only the src side has a port: it is the server ONLY if it is a
        # recognised service port, never a lone ephemeral client port.
        server_is_src = src_server
    else:
        # dst carries the only port, or neither side does: keep the
        # conventional src=client / dst=server orientation.
        server_is_src = False
    if server_is_src:
        return dst_endpoint, src_endpoint, sp
    return src_endpoint, dst_endpoint, dp


def _capture_key(session: NetworkSession) -> str:
    # The capture FILE is the identity: since VD-02a every upload gets a
    # PcapCapture row, and re-uploading the same file must refresh its
    # findings, not duplicate them (a re-upload re-links the sessions to the
    # new capture row).
    if session.source_file:
        digest = hashlib.sha1(session.source_file.encode("utf-8", "replace")).hexdigest()[:12]
        return f"file:{digest}"
    if session.pcap_capture_id is not None:
        return f"capture:{session.pcap_capture_id}"
    return "capture:none"


def _is_classified_ews(host) -> bool:
    """RS-08: a host the operator classified as an engineering workstation
    at site operations (L3) or below."""
    return bool(host is not None and host.device_type == "engineering_workstation"
                and host.purdue_level is not None and float(host.purdue_level) <= 3)


def _write_wording(ev: dict, client) -> tuple:
    """(severity, title, evidence additions) of an industrial-write finding.
    RS-08: from a classified engineering workstation it is engineering access
    to approve (high), otherwise an unauthorized write (critical)."""
    op, summary = ev.get("operation"), ev.get("summary")
    what = "write" if op == "write" else f"{summary} ({op})"
    src_txt = ev.get("src_ip") or ev.get("src_mac") or "unknown host"
    dst_txt = ev.get("dst_ip") or ev.get("dst_mac") or "unknown host"
    n = ev.get("occurrences")
    if _is_classified_ews(client):
        return ("high",
                (f"Engineering access to approve: {ev.get('protocol')} {what} from engineering workstation "
                 f"{src_txt} to {dst_txt} (x{n}) - not an approved engineering source")[:512],
                {"engineering_ws": True,
                 "severity_reason": ("High: the source is classified as an engineering workstation but is not "
                                     "an approved engineering source; approve it or investigate the operation.")})
    return ("critical", f"Unauthorized {ev.get('protocol')} {what} from {src_txt} to {dst_txt} (x{n})"[:512],
            {"engineering_ws": False, "severity_reason": None})


def refresh_write_wording(db: DBSession) -> int:
    """RS-08: re-word open industrial-write findings when their source's
    classification changed since the capture was uploaded."""
    from app.parsers.site_scope import current_site as _cs
    sid = _cs(db)
    n = 0
    q = db.query(Finding).filter(Finding.check_name == "unauthorized_industrial_write",
                                 Finding.status.in_(ACTIVE_FINDING_STATUSES))
    if sid is not None:
        q = q.filter(Finding.site_id == sid)
    for f in q.all():
        ev = dict(f.detail or {})
        ip = ev.get("src_ip")
        host = None
        if ip:
            hq = db.query(Host).filter(Host.ip == ip)
            if sid is not None:
                hq = hq.filter(Host.site_id == sid)
            host = hq.first()
        sev, title, extra = _write_wording(ev, host)
        if (f.title, f.severity) != (title, sev):
            f.title, f.severity = title, sev
            f.detail = {**ev, **extra}
            n += 1
    return n



def check_unauthorized_industrial_writes(db: DBSession, commit: bool = True,
                                        close_stale: bool = False) -> dict:
    """
    Checklist 8.4 (SR 2.1, SR 3.5): "Industrial write/program operations
    only from authorized hosts."

    The protocol analyzers (modbus_analyzer.py, dnp3_analyzer.py,
    s7comm_analyzer.py, enip_cip_analyzer.py) decode an "operation" per
    frame. Flagged operations: "write", plus the high-impact "program"
    (S7 block download/upload) and "control" (S7 PLC STOP/control, DNP3
    restart/initialize/start/stop application).

    Only REQUESTS count (responses echo the same function code and used to
    double the findings), and the source is the CLIENT side of the session
    (inferred from the protocol's well-known server port). A request whose
    client is not covered by an ApprovedHost (role=engineering_ws or hmi,
    under the active Baseline; matched by IP/CIDR or by MAC) is flagged.

    Findings are DEDUPLICATED per (client host, server host, protocol,
    function/summary) per capture file (source file, else pcap_capture_id): one
    critical finding carrying an occurrence count and the first
    ProtocolDetail ids as evidence, rather than one finding per packet.
    source_ref = "industrial_op:<capture>:<protocol>:<summary>:<client>><server>".
    Re-running the check refreshes the occurrence count on the existing
    open finding instead of creating another.

    DELIBERATE "FAIL OPEN TO VISIBILITY" DESIGN CHOICE: if no
    ApprovedHost baseline data has been loaded at all (the common case
    until someone runs /ingest/baseline/approved-hosts), every flagged
    industrial operation is reported rather than the check silently
    producing zero findings. Each finding's detail dict says plainly when
    this is why it fired.

    commit=False only flushes, leaving the transaction to the caller.

    close_stale (review runs, after NAT reconciliation P-04 / P-05): open
    findings whose (client, server) identity no current request produces
    any more - the sessions were re-attributed to the real source / mapped
    host - are closed; the re-attributed finding replaces them.
    """
    stats = {"writes_examined": 0, "responses_ignored": 0, "high_impact_ops": 0,
             "findings_created": 0, "already_flagged": 0}
    approved_networks, approved_macs = _get_approved_engineering_hosts(db)
    approved_any = bool(approved_networks or approved_macs)
    now = datetime.now(timezone.utc)

    # Eagerly load session and both hosts in one query to avoid N+2 per-row
    # lookups inside the loop. (P4-M6)
    # B-06 / AU full review B10: keyset-paginated (one row per decoded frame -
    # never the whole table in memory); the grouping below is incremental.
    def _details():
        last = 0
        while True:
            batch = (db.query(ProtocolDetail)
                     .filter(ProtocolDetail.protocol.in_(_WRITE_CAPABLE_PROTOCOLS), ProtocolDetail.id > last)
                     .options(joinedload(ProtocolDetail.session).joinedload(NetworkSession.src_host),
                              joinedload(ProtocolDetail.session).joinedload(NetworkSession.dst_host))
                     .order_by(ProtocolDetail.id).limit(2000).all())
            if not batch:
                return
            yield from batch
            last = batch[-1].id
            if len(batch) < 2000:
                return

    groups: dict = {}
    for detail in _details():
        fields = detail.fields if isinstance(detail.fields, dict) else {}
        operation = fields.get("operation")
        if operation not in _FLAGGED_OPERATIONS:
            continue
        if not _is_request(detail):
            stats["responses_ignored"] += 1
            continue
        stats["writes_examined"] += 1
        if operation in _HIGH_IMPACT_OPERATIONS:
            stats["high_impact_ops"] += 1

        session = detail.session
        if not session:
            continue
        client, server = _client_server(session, detail.protocol)
        if not client:
            continue
        if _host_is_approved(client.ip, approved_networks, client.mac, approved_macs):
            continue  # legitimate engineering/HMI operation - no finding

        summary = detail.summary or fields.get("summary") or operation
        key = (
            _capture_key(session), detail.protocol, summary,
            client.id, server.id if server else None,
        )
        group = groups.get(key)
        if group is None:
            groups[key] = group = {
                "detail_ids": [], "count": 0, "session": session, "client": client,
                "server": server, "protocol": detail.protocol, "summary": summary,
                "operation": operation, "first_ts": detail.timestamp, "last_ts": detail.timestamp,
            }
        group["count"] += 1
        if len(group["detail_ids"]) < _MAX_DETAIL_IDS_IN_EVIDENCE:
            group["detail_ids"].append(detail.id)
        if detail.timestamp is not None:
            if group["first_ts"] is None or detail.timestamp < group["first_ts"]:
                group["first_ts"] = detail.timestamp
            if group["last_ts"] is None or detail.timestamp > group["last_ts"]:
                group["last_ts"] = detail.timestamp

    # FO-12: without an approved list every write is reported (fail open);
    # name the likely engineering workstation(s) - program / control
    # operations first, then the most writes
    stats["fail_open"] = not approved_any
    if not approved_any and groups:
        score: dict = {}
        for g in groups.values():
            c = g["client"]
            rec = score.setdefault(c.ip, {
                "ip": c.ip, "program_ops": 0, "writes": 0, "targets": set(),
                # IO-11: an operator-classified or level-known host is identified
                "identified": bool(c.classification_source == "manual" or (
                    c.purdue_level is not None
                    and c.device_type not in (None, "ics_protocol_client_unclassified")))})
            if g["operation"] in _HIGH_IMPACT_OPERATIONS:
                rec["program_ops"] += g["count"]
            else:
                rec["writes"] += g["count"]
            if g["server"] is not None and g["server"].ip:
                rec["targets"].add(g["server"].ip)
        ranked = sorted(score.values(), key=lambda r: (-r["program_ops"], -r["writes"], r["ip"]))
        stats["engineering_candidates"] = [
            {**r, "targets": sorted(r["targets"])} for r in ranked[:3]]

    if not groups:
        if close_stale:
            stats["closed_stale"] = _close_stale_writes(db, set())
        _finish(db, commit)
        return stats

    # A-16: dedup against ACTIVE findings (open or acknowledged, preferring
    # open) - same semantics as alert_engine._find_open: an acknowledged
    # finding is owned by a person and a persisting condition must update
    # it, not spawn a fresh open duplicate on every run.
    from app.parsers.alert_engine import _ACTIVE_STATUSES, _find_open, _redetected
    existing: dict = {}
    for f in (db.query(Finding)
              .filter(Finding.source_ref.like("industrial_op:%"),
                      Finding.status.in_(_ACTIVE_STATUSES))
              .order_by(Finding.id).all()):
        cur = existing.get(f.source_ref)
        if cur is None or (cur.status != "open" and f.status == "open"):
            existing[f.source_ref] = f

    for (capture, protocol, summary, client_id, server_id), group in groups.items():
        source_ref = f"industrial_op:{capture}:{protocol}:{summary}:{client_id}>{server_id}"[:255]
        client, server, session = group["client"], group["server"], group["session"]
        evidence = {
            "protocol": protocol,
            "summary": summary,
            "operation": group["operation"],
            "high_impact": group["operation"] in _HIGH_IMPACT_OPERATIONS,
            "occurrences": group["count"],
            "protocol_detail_ids": group["detail_ids"],
            "first_seen": group["first_ts"].isoformat() if group["first_ts"] else None,
            "last_seen": group["last_ts"].isoformat() if group["last_ts"] else None,
            "capture": capture,
            "src_ip": client.ip,
            "src_mac": client.mac,
            "dst_ip": server.ip if server else None,
            "dst_mac": server.mac if server else None,
            "session_id": session.id,
            "dst_port": _SERVER_PORTS.get(protocol, session.dst_port),
            **_nat_evidence(session),
            "checklist_title": "Industrial write/program operations only from authorized hosts",
            "approved_networks_checked": len(approved_networks),
            "approved_macs_checked": len(approved_macs),
            "note": None if approved_any else (
                "No ApprovedHost baseline data loaded for engineering_ws/hmi roles - "
                "every industrial write/program/control operation is being flagged for "
                "review until that baseline exists. See /ingest/baseline/approved-hosts."
            ),
        }
        sev, title, extra = _write_wording(evidence, client)
        evidence.update(extra)
        found = existing.get(source_ref)
        if found is not None:
            # A-16: re-detection like _make_finding (last_seen /
            # occurrence_count bumped, evidence refreshed).  RS-08: title and
            # severity follow the source's current classification.
            _redetected(found, {**(found.detail or {}), **evidence})
            if (found.title, found.severity) != (title, sev):
                found.title, found.severity = title, sev
            stats["already_flagged"] += 1
            continue

        finding = Finding(
            category="periodic_review",
            check_name="unauthorized_industrial_write",
            severity=sev,
            status="open",
            isa62443_sr="SR 2.1, SR 3.5",
            checklist_id="8.4",
            title=title,
            detail=evidence,
            session_id=session.id,
            source_ref=source_ref,
            created_at=now,
            site_id=current_site(db),
        )
        # A-16: savepoint per insert - a concurrent writer winning the open
        # slot (partial unique index) must not roll back the whole batch.
        sp = db.begin_nested()
        try:
            db.add(finding)
            sp.commit()
        except IntegrityError:
            sp.rollback()
            winner = _find_open(db, source_ref)
            if winner is not None:
                _redetected(winner, {**(winner.detail or {}), **evidence})
                existing[source_ref] = winner
            stats["already_flagged"] += 1
            continue
        existing[source_ref] = finding
        stats["findings_created"] += 1

    if close_stale:
        produced = {f"industrial_op:{c}:{p}:{s_}:{ci}>{si}"[:255]
                    for (c, p, s_, ci, si) in groups}
        stats["closed_stale"] = _close_stale_writes(db, produced)
    _finish(db, commit)
    return stats


def _close_stale_writes(db: DBSession, produced: set) -> int:
    from app.models import NetworkSession
    now = datetime.now(timezone.utc)
    note = ("Auto-resolved: the write was re-attributed (NAT: the session's real source / "
            f"destination) ({now.strftime('%Y-%m-%dT%H:%M:%SZ')})")
    n = 0
    for f in db.query(Finding).filter(Finding.check_name == "unauthorized_industrial_write",
                                      Finding.status == "open",
                                      Finding.source_ref.like("industrial_op:%")):
        if f.source_ref in produced:
            continue
        sess = db.get(NetworkSession, f.session_id) if f.session_id else None
        if sess is None or not (sess.nat_orig_dst_ip or sess.nat_orig_src_ip):
            continue        # only findings whose session NAT re-attribution changed
        f.status, f.closed_at, f.updated_at = "closed", now, now
        f.notes = ((f.notes + " | ") if f.notes else "") + note
        n += 1
    return n


def _nat_evidence(session) -> dict:
    """P-04 / P-05: how a NAT'd session was captured."""
    out = {}
    if getattr(session, "nat_orig_dst_ip", None):
        out["captured_dst_ip"] = session.nat_orig_dst_ip
    if getattr(session, "nat_orig_src_ip", None):
        out["captured_src_ip"] = session.nat_orig_src_ip
    nat = getattr(session, "nat", None) or {}
    if nat.get("events"):
        out["nat"] = nat["events"]
    if nat.get("unattributed"):
        u = nat["unattributed"]
        out["source_hidden_by_nat"] = u
        out["nat_note"] = (f"The source {session.src_host.ip if session.src_host else ''} is the address "
                           f"{u.get('firewall')} translates to (policy {u.get('policy_id')} "
                           f"{u.get('policy_name') or ''}); the real client is one of "
                           f"{u.get('original_sources')} and is not in the capture.")
    return out


def _finish(db: DBSession, commit: bool) -> None:
    if commit:
        db.commit()
    else:
        db.flush()


# Multi-site (phase 2): public entry points take an optional keyword-only
# site_id and then run scoped to that site (app.parsers.site_scope): every
# query sees only that site's rows and created findings land in it.
scope_module(globals(), ("check_",))
