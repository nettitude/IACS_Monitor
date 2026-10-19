# Finding explanations ("Why this was flagged")

Every finding has an explanation from `GET /findings/{id}/explanation` (`app/explain.py`). In the UI it opens in a pop-up window: the **?** button on each finding row, or **Why this was flagged…** in the finding panel (which otherwise shows only a one-line severity reason and the collapsed raw evidence). Esc, the backdrop or Close dismisses it. The PDF report does not include the explanation (owner decision).

| Part | Content | Source |
|---|---|---|
| What was found | The finding's own analysis, key facts (device, policy, source / destination, VPN group, segment, NAT ...), and for path findings the hop list: each firewall and policy, the NAT at each step, traffic seen | The finding's evidence |
| Why it is an issue | The risk in plain language | Catalogue entry per check (every check in the catalogue - 179 at 2026-10-15) |
| Requirement | IEC 62443-3-3 SR(s), other references (e.g. 62443-2-4 SP.07), and the workbook row(s) with their 62443 / NIST references | Check registry + workbook (`app/checklist_rows.py`) |
| Why this severity | Why the finding has its level | Recorded by the check (`severity_reason`), else derived (default severity, raised because seen in the capture, high-impact operation, ...) |
| How to resolve | What to change, including the Fix options where the app offers them (declare a management / engineering source, cell/area zone, VPN group category, Access Review exception) | Catalogue |
| How it closes | Auto-resolve on the next review run / config upload, approval, attestation, acknowledgement | Catalogue, else by category |
| How to verify by hand | The workbook's "How to verify (FortiOS / Analysis)" text for the row | Workbook |
| All evidence fields (raw) | Every stored field, collapsed | The finding |

Checks that record their severity reason: the chain checks (bypass, management, upward skip, dead end), DMZ bypass, internet egress, VPN to OT, flat control segment, source NAT into OT, unused VIP and the session IT/OT bypass. When a finding re-occurs at a lower severity it keeps its higher severity and the reason that set it.

## Workbook row mapping

Owner decision: the checks keep the workbook edition they were mapped against. The explanation shows each row as the check states it (the finding's `checklist_title`, else the app's row titles in `app/checklist_rows.py`). The uploaded `OT_Firewall_Review_62443_Checklist.xlsx` (73 rows, also in `app/checklist_rows.py`) supplies the 62443 / NIST references and the "How to verify" text only for rows whose text matches the check; for the rows that differ in that edition (1.1-1.6, 2.3, 2.5, 2.6, 3.10, 7.1, 7.2, 7.5, 7.7, 7.8, 8.10, 9.3) they are left out rather than attributed to the wrong control.
