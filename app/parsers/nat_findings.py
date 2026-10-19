"""
NAT checks (NAT tabletop P-07, P-08).

``nat_hides_source_into_ot`` (medium; SR 2.8 auditable events, SR 6.2;
workbook row 6.1) - owner: nothing may move into OT without accountability.
One finding per source-NAT policy that translates the source of a permitted
path INTO an OT level (L0-L3; L3 is OT) from a higher level: the OT devices,
their logs and any capture behind the firewall see only the translated
address, not who connected.  Evidence: the paths, the original sources, the
translated address, and how many captured sessions arrived translated
(attributed to a real client from a pre-NAT capture, or not).

``config_vip_unused`` (medium; SR 7.7, SR 5.2; row 3.8) is raised at config
upload (forti_config_parser._hardening_findings): a VIP no enabled policy
references - a published address waiting to be used.
"""
from __future__ import annotations

import logging

from sqlalchemy.orm import Session as DBSession

log = logging.getLogger(__name__)

CHECK = "nat_hides_source_into_ot"
OT_MAX = 3


def review_nat_hides_source_into_ot(db: DBSession) -> list:
    from app.models import NetworkSession
    from app.parsers import alert_engine as ae
    from app.parsers import chain_findings as cf
    from app.parsers.access_path_findings import path_label
    from app.purdue import fmt_level
    rows = [r for r in cf._candidates(db, ae, direction="down", multi_only=False)
            if "source_nat" in (r.get("flags") or [])
            and (r.get("dst") or {}).get("level") is not None
            and (r.get("dst") or {}).get("level") <= OT_MAX]
    groups: dict = {}
    for r in rows:
        for e in r.get("nat") or []:
            if e.get("type") != "snat":
                continue
            groups.setdefault((e.get("firewall_id"), str(e.get("policy_id"))), (e, []))[1].append(r)
    if not groups:
        return []
    sessions = [n for (n,) in db.query(NetworkSession.nat).filter(NetworkSession.nat.isnot(None))]
    out = []
    for (fid, pid), (e, members) in groups.items():
        unattr = sum(1 for n in sessions if (n.get("unattributed") or {}).get("firewall_id") == fid
                     and str((n.get("unattributed") or {}).get("policy_id")) == pid)
        attributed = sum(1 for n in sessions if n.get("attributed_from_session")
                         and any(ev.get("type") == "snat" and ev.get("firewall_id") == fid
                                 and str(ev.get("policy_id")) == pid for ev in n.get("events") or []))
        sources = []
        for m in members:
            s = (m.get("src") or {}).get("scope")
            if s and s not in sources:
                sources.append(s)
        labels = []
        for m in members:
            lb = path_label(m)
            if lb not in labels:
                labels.append(lb)
        lowest = min((m.get("dst") or {}).get("level") for m in members)
        seen = any(cf._seen(m) for m in members) or unattr or attributed
        title = (f"Source NAT into OT: {e.get('firewall')} policy {pid} hides "
                 f"{', '.join(sources[:3])} behind {e.get('translated_to')} toward "
                 f"{fmt_level(lowest)}" + (" [seen in capture]" if seen else ""))
        text = (f"{e.get('firewall')} policy {pid} ({e.get('name')}) translates the source of traffic "
                f"into the OT zone to {e.get('translated_to')}: {'; '.join(labels[:5])}. The OT "
                f"devices, their logs and any capture behind the firewall see only "
                f"{e.get('translated_to')}, not which of {', '.join(sources[:5])} connected - "
                f"nothing should enter OT without accountability (IEC 62443-3-3 SR 2.8 auditable "
                f"events, SR 6.2 continuous monitoring). "
                + (f"{unattr} captured session(s) arrived translated with no pre-NAT capture to "
                   f"name the real client. " if unattr else "")
                + (f"{attributed} captured session(s) were attributed to their real client from a "
                   f"pre-NAT capture of the same flow. " if attributed else "")
                + "Remove the source NAT on paths into OT (route the real addresses), or keep the "
                  "firewall's session log with the original source where the OT side can be "
                  "audited.")
        f = ae._make_finding(
            db, CHECK, title[:512], text,
            {"firewall": e.get("firewall"), "firewall_id": fid, "policy_id": pid,
             "nat_rule": e.get("name"), "translated_to": e.get("translated_to"),
             "original_sources": sources, "paths": labels[:20],
             "dst_level": lowest, "sessions_unattributed": unattr,
             "severity_reason": "Medium (owner decision): nothing may enter OT without "
                                "accountability for its real source.",
             "sessions_attributed": attributed,
             "access_path_tags": [m.get("tag_key") for m in members][:50]},
            severity="medium", dedup_evidence={"rule_key": f"nat_hides_source:{fid}:{pid}"})
        if f is not None:
            out.append(f)
    return out
