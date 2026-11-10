# IACS_Monitor — notes for Claude Code

Handoff from the claude.ai project "Network hound" (2026-10-12). Read this first; the full
history of every change is in `docs/code-review-remediation.md` (the tracker).

## What this is

A passive IEC 62443 / ISA-99 compliance monitor for OT networks. It ingests firewall configs
(FortiGate primarily; Cisco ASA/IOS, PAN-OS, pfSense), syslog (FortiGate, ASA, PAN-OS, pfSense),
PCAPs (Modbus, S7, DNP3, ENIP/CIP, PROFINET, SMB, ...), Cisco/HP switch outputs, ARP/MAC tables
and baseline CSVs, places hosts and firewall interfaces on Purdue levels (L0–L5, plus L3.5 DMZ),
and raises findings mapped to 62443-3-3 SRs, checklist rows, FR and SL. Multi-site.

- FastAPI + SQLAlchemy 2 + Alembic; SQLite by default, PostgreSQL supported.
- Single-file console: `ui/index.html` (served at `/ui`; `/ui/topology` = standalone Host Topology).
- PDF report: `generate_report.py` (reportlab; CLI and `GET /reports/compliance.pdf`).
- Python 3.11.15. Dependencies pinned in `requirements-lock.txt` (installed with `--no-deps`).

## Current state

- Release **2026.10.09.38** (2026-11-09). Alembic head **`c5d6e7f8a9b0`** (unreleased, `port_security_mode`). **185 checks**. Full suite **2867 passed, 11 skipped** (2026-11-09, after the owner batch; unreleased).
- Full suite: **2855 passed, 11 skipped** (timing-budget tests can fail under load, pass alone) on the owner's Mac (7 skips need PostgreSQL server
  binaries, 4 legacy-DB snapshots; the cloud had 1 skip). Flaky health test deselected, see Testing.
- UI smoke: 21 sections in `ui_smoke_index.py` (19 ran 19/19 on .16; `nettopo`, `fwports` written 2026-10-16/17, not yet run - Playwright not installed; `lanematrix` removed 2026-10-18) and 7/7 (`ui_smoke_pages.py`).

## Owner's standing rules (do not break)

1. **Never modify `./iasc_monitor.db`** — the operator's real database. `tests/conftest.py`
   fails the run if it changes. Never open it from tests or scripts.
2. **Code always runs as a fresh install.** Legacy-DB upgrade paths are out of scope (B-01,
   B-22 Won't fix). A fresh `alembic upgrade head` must still match the models exactly.
3. **No download files / packages until the owner says so.** Don't build tarballs or images
   unprompted.
4. **Deferred by owner:** A-01 (API authentication / CSRF) and H-01 (dual-homed historian).
   Don't start them unasked.
5. **Cisco switches only** for routing-switch support (no other switch vendors for L3).
6. **Tabletop scenario data, docs and generators stay out of the repo** (they live in
   `../project-docs/` of the handoff, not under `iasc_monitor/`).
7. **"No OT device should have direct access to the internet."** OT-egress findings always
   apply, are never closed by an External-comms approval, never lowered by a conduit.
8. **RS-08 option (a):** a classified engineering workstation's work on controllers is
   engineering access to approve (`engineering_access_unapproved`), not an IT-to-OT bypass.
9. The owner decides new checks, severities and behaviour changes. When a fix needs a design
   choice, propose options (with a recommendation) and wait.

## Layout

```
app/main.py              app start, middleware, scheduler (flock single-instance)
app/api/routes.py        every HTTP route (~8.7k lines); route table guarded by tests/test_cov_routes.py
app/models.py            ORM models + CHECK_TYPE_REFERENCE (check -> SR, rows, severity, category)
app/db.py                engines, SQLite pragmas (WAL, FKs, BEGIN IMMEDIATE for writes)
app/purdue.py            Purdue levels (single source of truth, L3.5)
app/security_levels.py   62443-3-3 SR -> FR / SL table
app/explain.py           "Why this was flagged" text per check (_e(...) entries)
app/sites.py, site_devices.py   multi-site, device registry, held log lines
app/iec_zones.py         IEC 62443-3-2 zones/conduits (view only; see rule below)
app/zone_findings.py     the only checks sourced from zones
app/parsers/alert_engine.py     findings engine (~9.2k lines): real-time checks, periodic reviews,
                                rule twins (review_rule_*), _make_finding, run_periodic_reviews
app/parsers/forti_config_parser.py  FortiOS config -> rules/zones/NAT + config_* checks (_config_findings)
app/parsers/firewall_parser.py, fw_interfaces.py   Cisco/PAN/pfSense rules + interfaces
app/parsers/reachability.py     level matrix + host path queries (enforcement points, series/OR)
app/parsers/subnet_topology.py  Network Topology: lanes by subnet / VLAN, flows, separators, egress
app/parsers/port_topology.py    Firewall Ports: ports, VLAN sub-interfaces, permitted services between interfaces
app/parsers/fortiswitch_parser.py  FortiLink-managed FortiSwitches from the FortiGate backup -> switch rows
app/writeup.py           per-check write-up: concern, references (SR titles, NIST, CIS), FortiOS example templates
app/config_store.py      stored (masked) firewall config text, snippets per finding
app/report_checks.py     check groups / per-site report selection; app/check_evaluations.py = PASS / NOT EVALUATED
app/findings_workbook.py xlsx export / import of findings; make_check_reference_xlsx.py = check reference workbook
app/parsers/access_paths.py     Access Review enumeration; access_path_groups.py = roll-up keys
app/parsers/chain_findings.py   chain_* / path_* / dead_end findings from access paths
app/parsers/pcap_parser.py      PCAP ingest (reassembly, SPAN dedupe, capture point)
app/parsers/device_classification.py, subnet_zones.py   host Purdue classification
generate_report.py       PDF report
generate_audit_report.py Audit report (PDF + CSV) from the Master Audit Checklist workbook; app/audit_checklist.py reads it
ui/index.html            console (vanilla JS, el() DOM builder, textContent only)
alembic/versions/        51 migrations, all idempotent (alembic/iasc_migration_utils.py)
tests/                   pytest suite + Playwright smoke (ui_*.py, not collected)
docs/                    design docs, check reference (+ xlsx), docker guide, tracker
```

## Conventions that matter

- **One finding per logical rule / policy** (T3-19); dedup on stable keys (`rule_key`,
  `source_ref`), not row ids. Re-detection updates `last_seen`/`occurrence_count`; escalation
  updates the open finding (never a duplicate). Acknowledged and `false_positive` count as active.
- **Auto-resolve** only from complete review runs; mark partial input with `_mark_incomplete`.
- **Site scoping:** run engine code under `analysis_site(db, site_id)` / `ingest_site(...)`;
  Core statements and warm `Session.get` bypass the scope (docs/multi-site-design.md).
- **Migrations idempotent**, additive, fresh head must equal models (`tests/test_migrations.py`).
- **UI:** build DOM with `el()` / `textContent` only — the smoke seed plants XSS payloads and fails
  if any executes. Keyboard-operable rows; site-switch races guarded (`beginLoad`/`g.stale()`).
- **Zones never change other findings.** Parsers and `explain.py` must not import `iec_zones`;
  `alert_engine.py` references `zone_findings` only to run its reviews; `generate_report.py` uses
  `iec_zones` only in `collect_zone_data` (`test_engine_does_not_import_the_zone_module`).
- Interface labels decide levels; unlabelled sides are "direction unverified" / not judged
  (`GET /reviews/rules-not-judged`). A labelled interface's level applies to every host on its network
  except manual / subnet-declared ones (`subnet_zones._LABEL_KEEPS`, owner 2026-10-14).

### Adding a check (checklist)

1. Implement (rule twins: copy a `review_rule_*` in alert_engine.py; use `_collect_hits`,
   `_emit_twin`).
2. Register: `_RULE_TWIN_CHECKS`, `_TWIN_CHECK_NAME`, the auto-resolve map (`review_x: ("check",)`)
   — or `run_periodic_reviews` for other reviews.
3. `CHECK_TYPE_REFERENCE` in models.py (SR string drives FR/SL automatically).
4. `app/explain.py` `_e(...)` entry; `app/writeup.py` `CONCERN` (optional), `CIS` topic and a `FORTI`
   template for every FortiGate config check (`test_writeup` enforces it); `config_store.CHECK_SECTIONS`
   for the config snippet; `_config_evidence` row if the evidence page should show the setting.
5. `docs/62443-check-reference.md` row + bump the check count line; README check table + its count;
   regenerate the workbook (`make_check_reference_xlsx.py`); user manual if the page text changes.
6. If level-dependent: `_LEVEL_CHECKS` in generate_report.py; `_CHECK_INPUTS` only when the name
   prefix does not already map the inputs.
7. Tests: a focused test file + an entry in `tests/test_cov_alert_engine.py` COVERAGE map
   (every public alert_engine function must map to a test function in that file).
8. Watch `tests/test_cov_e2e.py` EXPECTED_CHECKS (snapshot of the sample data).

## Testing

```bash
pip install -r requirements-dev-lock.txt --no-deps     # or requirements-dev.txt
python -m pytest -q -p no:cacheprovider -rf \
  --deselect tests/test_health.py::test_health_stays_responsive_during_large_pcap_ingest
# ~10 min. The deselected test is timing-sensitive and flaky under load.
```

UI smoke (Playwright, Chromium). Each run needs a **fresh** seeded DB (they write to it; a
second run on the same DB fails the `sites` section with a 409):

```bash
python tests/ui_demo_server.py --db /tmp/ui1.db --port 8196 &
python tests/ui_smoke_index.py http://127.0.0.1:8196 --shots /tmp/shots_index
python tests/ui_smoke_pages.py http://127.0.0.1:8196
```

Add a smoke check for every UI feature (sections in `ui_smoke_index.py`, e.g. `fw_policy_lines`,
`fw_zone_hover`, `ar_rollup`, `assets_import`).

## Release routine (only when the owner asks)

Version scheme `2026.10.09.N` (last: .38). From the parent directory of the repo:

```bash
V=2026.10.09.39
tar czf iasc_monitor-$V-full.tar.gz \
  --exclude='iasc_monitor/iasc_monitor.db*' --exclude='iasc_monitor/*.db' \
  --exclude='iasc_monitor/iasc_scheduler.lock' --exclude='iasc_monitor/*.pdf' \
  --exclude='iasc_monitor/dist' --exclude='__pycache__' --exclude='*.pyc' \
  --exclude='.pytest_cache' --exclude='iasc_monitor/.coverage' iasc_monitor
sha256sum iasc_monitor-$V-full.tar.gz > iasc_monitor-$V-full.tar.gz.sha256
(cd iasc_monitor && bash make-dist.sh $V --out ..)      # install tarball + sha256
```

Docker: build from the extracted full tarball. **Always pass `--target`** — the Dockerfile's last
stage is `dev`, so a build without it produces the dev image:

```bash
docker build --target runtime -t iasc-monitor:$V -t iasc-monitor:latest .
docker build --target dev     -t iasc-monitor:$V-dev -t iasc-monitor:dev .
```

(The cloud build used a stand-in base `--build-arg PYTHON_BASE=iasc-standin-python:3.11.15-clean`
plus `--network host` and a proxy CA secret because Docker Hub was unreachable; on a normal
machine the default `python:3.11-slim-bookworm` base works.) Verify on a fresh volume: `/health`,
`/ui` 200, `GET /sites` = `[]`, runs as `iasc`, `alembic current` = head, runtime image has no
pytest. `docker-compose.yml`, `build.sh` and docs/docker-install.md already use `--target runtime`.

## Docs to keep in step

- `docs/code-review-remediation.md` — the tracker. Add a section per change (what, why,
  owner's words, tests, suite result) before "## Upgrade notes for existing installs", and an
  upgrade-note bullet at the end.
- README (routes, Web UI rows, check table, limitations), `docs/62443-check-reference.md`,
  the relevant design doc (`access-path-review.md`, `firewall-groups.md`, ...).
- Design / tabletop docs that are not in the repo: `../project-docs/` (iec-zones-conduits,
  segmented-firewall / routed-ot / isolated-ot tabletops, vlan-topology-implementation).

## Recent work (2026-10-11 .. 12, all in .16)

- Access Review roll-up: rows differing only in one host are one line (screen + PDF);
  `group_dst`/`group_src` on `/access-paths` rows; toggle "Roll up similar paths".
- Light console theme (no dark toggle; old dark theme not kept in the repo).
- Firewall Devices rules: one line per policy (toggle), hover on zone names (networks + hosts),
  hover on Source/Destination (every consolidated host resolved against the inventory).
- `rule_dns_external` (any permit to an external DNS server on tcp/udp 53; high from OT) and
  `config_dns_external` naming every external resolver incl. the FortiGuard default.
- Asset Inventory CSV import with column mapping (preview, checks, saved mappings per site).
- SF-5 / SF-6: `blocked_cross_zone_attempts`, `conduit_service_blocked`,
  `policy_spans_multiple_conduits`; IEC zones: SL-C/SL-T/SL-A, multi-zone findings,
  `undocumented_conduit`, service-aware severity lowering (view only).

## In .17 (2026-10-12)

- Cleartext / management split: `rule_cleartext_protocol` / `cleartext_protocol` (renamed from
  *insecure*), new `rule_mgmt_protocol` / `mgmt_protocol`; Telnet / SNMP raise both.
- Access Review bulk bar: Note / By / Set note (one note on many rows; Apply saves it with the
  classification).
- Mac notes: venv `.venv` (radioconda Python 3.11.7); Playwright not installed; package with
  GNU tools (build the tarballs in a Linux container); `.env` holds `IACS_ENABLE_DELETE=true` (not shipped).

## In .18 (2026-10-12)

- Firewall Devices rules: Source / Destination hover is interactive; *Classify level / zone…* saves
  Subnets & Zones declarations (/32 per host) for the ticked values (`fwClassifyOpen`; smoke `fw_classify`).
- Shadow Rules: one card per policy pair (toggle *One card per policy pair*; `shadowGroups`).
- FW Topology Builder: disabled (admin-down) interfaces hidden by default, *Show disabled interfaces*
  draws them greyed; `/topology/state` interfaces carry `status` / `enabled`.
- Logging: every log destination counts (`_log_destinations`); `config_no_syslog_forwarding` row 6.3; new
  `config_monitoring_readiness` (156 checks); FortiGuard NTP / DNS info / low (WAN leg, FQDN rules, OT).
- PDF: PASS / NOT EVALUATED per check from `check_evaluations` (migration `9b0c1d2e3f4a`, written by
  site-bound review runs and FortiGate uploads; `app/check_evaluations.py`) + Configuration Evidence
  appendix per FortiGate (`_config_evidence`).
- Host VLAN from the firewall / L3-switch VLAN interface subnet (`assign_vlans_from_interfaces` in
  classify_hosts, `vlan_source` `fw_interface`, `/assets` `vlan_origin`).
- Interface aliases (`set alias`) shown in grey on the device card, rules Zones column, zone hover and
  FW Topology Builder cards; `alias` on `/firewall-zones` and `/topology/state` (display only).

## In .19 (2026-10-12)

- Periodic reviews run at upload time (`app/review_trigger.py`, `_reviews_after_upload` on the upload
  routes; `IACS_REVIEW_ON_UPLOAD`, off in the test suite).
- Firewall Devices NAT drill-down: one line per NAT policy / VIP (`natGroups`, same *One line per policy*
  setting as the rules page).
- Firewall Devices: card counts are policy lines (`policy_count` etc.), VPN policies badged / filterable
  (`/firewall-zones` `tunnel`, `fwRuleVpn`, `fwVpnNode`) with their user groups (`/vpn/groups`).
- Findings page: selection in place (`selectFindingRow`, no list rebuild), Prev / Next step by finding
  across pages (`findingsStep`).

## In .20 (2026-10-12)

- Checklist rows fixed: `config_ids_ips_missing` 3.12; `config_av_missing_on_file_policy`, `fqdn_in_policy`
  no row (SR only; PDF "Not in the checklist").
- 3.2 broadened: `config_permit_any_any_any` = 'all' in ANY position (critical all three, high into OT /
  Internet, medium); new `config_temporary_rule` (3.11; 157 checks).
- Mgmt & Engineering: disabled interfaces hidden / greyed (shared *Show disabled interfaces* setting).
- Admin access on a disabled interface: `config_mgmt_not_restricted_to_mgmt_zone` / `config_insecure_mgmt_protocol`
  kept at low ("(interface disabled)").
- Access Review flag `insecure_protocol` split into `cleartext_protocol` / `mgmt_protocol` (same port tables as the
  findings, imported from alert_engine; PDF maps each to its own check).

## In .21 (2026-10-13)

- Always one site: no *All sites* in the console / findings / fw-topology / attestation pickers; remembered site,
  else default / first (`loadSites`, `initSiteFilter`). Cross-site: Sites overview, PDF roll-up.
- Asset Inventory: row selected in place (`selectAssetRow`), rebuilds keep the scroll (`keepScroll`).
- Device types `site_dns_server` / `site_ntp_server` (L3), `enterprise_dns_server` / `enterprise_ntp_server` (L4).
- Host Topology drag and drop between level lanes (`topoDragStart` / `topoConfirmMove`, bar `#topo-move`); the
  classification PATCH takes `purdue_level` without `device_type` (type kept).

## In .22 (2026-10-13)

- Host Topology drag: empty L5 / L3.5 lanes shown while dragging; Unclassified pins any host
  (`PATCH ...classification?unclassified=true`, manual, no level) or returns a hand-set one to automatic.
- Host Topology multi-homed devices: one red card per subnet (`topoMultiHomed`, `topoSubnetKey`), red dashed
  "DMZ bypass" link (`mhLinkLabel`); drag moves only that address; Classify same-MAC default off for them.

## In .23 (2026-10-14)

- Multi-homed detection keys each address by its own subnet inside a shared capture segment
  (`topoSubnetKey` / `ipInCidr`), so a device on one flat segment still splits into one card per address.
- `auth_failure` / `auth_from_non_admin_host` recognise FortiOS 7.x admin logins (`subtype=system`,
  `action=login`, outcome in `status=` / logid 0100032001-2; `_login_outcome`).
- Asset Inventory IEC 62443 zone: `/assets` `iec_zone(s)`, PATCH `iec_zone` (`iec_zones.set_host_zone`), export `zone`,
  Zone column / filter / panel field.
- Security levels 0-4 with labels (`security_levels.SL_LABELS` / `parse_level_value`; SL0 is a level, never "not set" -
  use `sl_set` / `sl_below`); migration `ac1d2e3f4a5b` (SL-T checks allow 0, `iec_conduit_rules`).
- Conduit rule numbers (`add_conduit_rules`, `/iec-conduits/{id}/rules`, chips + hover `iecRulesCell` / `iecRulePop`);
  conduit SL-A on the add card; zones-table SL-A editable; host SL-C in "Hosts in no zone"; Subnets & Zones = menu sub-item.
- Findings next to their objects: `app/finding_links.py`, `/findings/linked`, `/findings/link-counts`; console
  `findingsSection`, side drawer (`openAssetDrawer` / `openFindingsDrawer`), saves re-run reviews (`recheckFindings`).
- Report target SL list SL0-SL4 with labels (`normalize_sl` accepts 0).
- `unknown_device`: a host approved on the Inventory page is known (`_page_approved`, both paths).
- Checks in the report: `app/report_checks.py`, `/reports/check-selection`, table `report_check_exclusions`
  (migration `bd2e3f4a5b6c`); the PDF leaves excluded checks out and lists them; `all_checks` / `--all-checks`.

## In .24 (2026-10-14)

- Audit fixes: conduit firewall matched exactly (no LIKE wildcards), ambiguous multi-VDOM policy refused, skipped
  `/reviews/run` reported by `recheckFindings`, one load guard per findings section, Findings SL filter labelled.

## In .25 (2026-10-14)

- Findings of excluded checks hidden app-wide (`report_checks.hidden_clause` via `_rc_hide` in every findings
  read, `LinkIndex`, site counts); `include_excluded=true` / Findings page toggle; reviews unchanged.
- PDF `include_closed`: closed findings in their own *Closed Findings* section (`build_closed_findings`,
  `closed_findings` / `closed_total`); the findings in scope are always open + acknowledged.
- Interface label level wins over every automatic host level (`_LABEL_KEEPS`); `segments._lvl` judges labelled
  hosts by their device type; menu: FW Topology Builder above Host Topology.
- Findings workbook: `app/findings_workbook.py` (openpyxl), `/findings/export.xlsx`, `/findings/import.xlsx`
  (dry run default); status rules shared via `routes.apply_finding_status`; Reports page card.

## In .26 (2026-10-14)

- PDF section *Shadowed and Redundant Rules* (`build_shadow_rules`): shadow_rule findings as rule pairs per firewall.

## In .27 (2026-10-14)

- Stored firewall config + config lines behind findings: `app/config_store.py` (`mask_secrets` before storing, latest upload
  per Firewall, zlib; `snippet_for_finding` = FortiOS block finder / `CHECK_SECTIONS` / Cisco `raw_line`), table
  `firewall_config_texts` (migration `ce3f4a5b6c7d`, head), `GET /firewalls/{id}/config`, `GET /findings/{id}/config-snippet`;
  console: *Config* on the device card (`openConfigDrawer`), *Configuration lines* in the finding panels (`configSnippetBlock`).
  Console only (not in the PDF) by owner's choice.
- `docs/user-manual.md`: the operator how-to (owner 2026-10-14 "create a how to use manual"); keep its version line and
  page table in step with UI changes.

## In .28 (2026-10-14)

- FW Topology Builder *Settings from the config* (owner 2026-10-14, option 3): `config_store.config_block`
  (FortiOS `forti_settings`, Cisco `cisco_stanza` / `cisco_settings` incl. nameif + access-group, `xml_element` /
  `xml_settings` for pfSense / PAN-OS), `GET /firewalls/{id}/config/block`, console `fwtConfigSettings` in `fwtRenderRight`.
- 2026-10-14: `CLAUDE.md` and `.claude/` disappeared from the checkout after the .27 build; CLAUDE.md was restored
  from the .27 full tarball (owner informed).

## In .29 (2026-10-15)

- Hosts excluded from the inventory (owner 2026-10-14; exclusion = a decision): `Host.inventory_excluded` (+ reason / by / at,
  migration `df4a5b6c7d8e`, head), `/assets` + export hide them unless `include_excluded` / `inventory=excluded|all`,
  `PATCH /assets/{id}` sets them, `_page_approved` counts them as known for `unknown_device`; console `inventoryExcludeBox`,
  filter options, "excluded" badge, Host Topology mark.

## In .30 (2026-10-15)

- Batch A of the evidence-matrix gap analysis (owner 2026-10-15 "implement batch A"): 14 FortiOS config checks
  in `_hardening_findings` (`config_strong_crypto_disabled`, `config_snmp_v1v2c_enabled`, `config_snmp_default_community`,
  `config_admin_no_two_factor` (per admin, only when an MFA means exists), `config_admin_profile_overprivileged`
  (> 2 super_admin), `config_no_login_banner`, `config_ha_no_monitor_interfaces`, `config_policy_any_interface`,
  `config_device_detection_disabled` (info roll-up), `config_ntp_unauthenticated`, `config_no_revision_backup`,
  `config_vendor_rule_permanent`, `config_implicit_deny_not_logged` (split out of `config_monitoring_readiness`))
  and `config_icmp_across_boundary` in `_config_findings`. **170 checks.** Evidence appendix rows, `CHECK_SECTIONS`,
  e2e snapshot (+5 on the sample config).

- Batch B (owner 2026-10-15 "do Batch B"): `config_vpn_user_no_mfa` (remote-access groups' local password users
  without two-factor; groups from SSL-VPN authentication-rules, dial-up `usrgrp`, VPN policy `groups`),
  `config_weak_ipsec_crypto` (explicit DES / 3DES / MD5 / DH 1-2-5 medium; SHA1 / no PFS low; per phase1 incl. its
  phase2s), `config_sslvpn_weak_tls` (`ssl-min-proto-ver` < TLS 1.2 or `algorithm` low / medium),
  `config_no_dos_policy_ot` (in `_config_findings`, OT interfaces from the labels via ctx `dos_policies`),
  `config_wireless_weak_security` (FortiAP VAP open / WEP / WPA1), and the periodic review `review_sis_isolation`
  -> `sis_zone_not_isolated` (hosts marked Safety function: sessions from / permit rules from non-safety,
  non-engineering sources, shared network). **176 checks.** `dos_anomaly` (real-time) was not added:
  `check_scanning_denied` already raises on FortiGate flood / DoS anomaly events.

- Batch C (owner 2026-10-15 "do batch c", PCAP evidence): `pcap_parser._default_credentials` / `_is_default_pair`
  (FTP / POP3 / SMTP AUTH PLAIN / HTTP Basic compared in the stream, kind "default credentials (<proto>)" only) and
  `_snmp_community` -> "(default)" for public / private; `_weak_transport` (TLS ServerHello SSLv3 / 1.0 / 1.1, SSH-1
  banner) -> ProtocolDetail rows protocol tls / ssh `fields.weak`; HTTP `Server:` and SSH-2 server banners ->
  ObservedName sources `http_server` / `ssh_banner`; CIP ListIdentity replies (`enip_cip_analyzer._parse_identity_reply`)
  and S7 read-SZL responses 0x0011 / 0x001C (`s7comm_analyzer._parse_szl_response`) -> `decoded["identity"]` ->
  `_apply_identity` fills Host model / firmware_version / serial_number / hostname when empty (+ ObservedName
  `cip_identity` / `s7_szl`). Reviews `review_transient_devices` (`transient_device_in_ot_zone`, `_TRANSIENT_OUI_WORDS`),
  `review_default_credentials` (`default_credentials_observed`), `review_weak_tls` (`weak_tls_observed`). **179 checks.**

- Audit 2026-10-15 (after batch C; tracker section "Audit of the unreleased work"): FortiOS `_tokens` never re-splits
  (quoted names stay whole), VDOM-qualified ids in `config_vendor_rule_permanent`, RADIUS counts as admin MFA only with
  `remote-auth`, DoS check only with an OT leg; PCAP identity applied to the sender, SSH-1 server-side only, S7 SZL
  version = Siemens layout; SIS review skips `all` destinations and resolves sources; `find_block` handles the VDOM
  declaration stub; `mask_secrets` covers the common Cisco / XML forms; drawer race guard + lazy section rendering;
  README check table and `docs/IACS_Monitor_62443_check_reference.xlsx` regenerated from `CHECK_TYPE_REFERENCE`
  (185 rows since 2026-10-19 - keep both in step when adding checks); `_CHECK_INPUTS` / `_LEVEL_CHECKS` for the new reviews.
- `make_check_reference_xlsx.py` (repo root) regenerates `docs/IACS_Monitor_62443_check_reference.xlsx` from the
  catalogue + explain texts + checklist rows (owner 2026-10-15); run it whenever checks change.

## In .31 (2026-10-16)

- Network Topology page (owner 2026-10-16, "a separate page, under the Host Topology page"): `app/parsers/subnet_topology.py`
  (`build`: lanes = firewall / SVI interface networks > capture segments > switch VLANs > inferred /24; WAN legs / tunnels / disabled interfaces are no lane; hosts with
  `function_of(device_type)`; separators per lane pair with sessions: firewall (policies between the interfaces / zones),
  routed_switch, flat (same capture L2 domain), unknown), `GET /topology/subnets`, console page `nettopo`
  (`loadNetTopo` / `renderNetTopo` / `ntDeclare` -> POST /subnets), nav sub-item under Host Topology, smoke `nettopo`.
  View only. Option 2 (same day): per-host `flows` (peer, lane, direction, protocol / port, packets, `between`; capped
  `MAX_FLOWS_PER_HOST` 40) shown by the card's `↔ n` badge (`nt-flow-badge`, F key); lanes carry `intra_sessions`.
  Option 3: *Lane Matrix* sub-page (`lanematrix`, `loadLaneMatrix` / `renderLaneMatrix`) - lanes x lanes session counts
  from the same route, cells coloured by separator kind, diagonal = intra-lane; smoke `lanematrix`.
  Egress lane (owner 2026-10-16, "private will be a sub-group within the egress lane"): `subnet_topology._egress`
  (External comms `flows` under `analysis_site`, grouped by destination; `private` sub-group; sources with `ot`;
  `by_lane`; WAN interfaces); public addresses are no longer lane hosts; console `ntEgressLane` / `ntEgressReview`
  (POST /external-comms/review), Lane Matrix *Egress* column (`k-egress-ot` red).

## In .32 (2026-10-17)

- Network Topology (owner 2026-10-17): interfaces with `status down` make no lane and no WAN leg
  (`subnet_topology.build` / `_egress`); the Declare card asks for the level and an optional zone name only
  (`created_by` = "Network Topology").
- Firewall Ports page (owner 2026-10-17, third nav sub-item under Host Topology, page `fwports`):
  `app/parsers/port_topology.py` `build(db, site_id)` - per firewall / routing switch the ports in config
  order (aggregate members folded from the stored config text via `_aggregate_members`; VLAN sub-interfaces
  on their parent via `parent_interface_id`, else the `name.tag` prefix), `kind_label`, per port the
  `subnets` (tag, network, alias, FortiOS zone - hidden when it merely repeats the interface name, label /
  declaration, host count); `links` = enabled permit rules expanded to interface pairs (zone names ->
  member interfaces), services `proto/port` or `ALL` with a kind from `_CLEARTEXT_PROTO_PORTS` /
  `_MGMT_PROTO_PORTS`, policy numbers, captured sessions per service, `into_ot`. Route `GET /topology/ports`.
  UI: `loadFwPorts` / `renderFwPorts` / `fpHover` / `fpPin` / `fpOpenPolicy` (opens the policy row on
  Firewall Devices), *show disabled ports* and *table view* toggles; Network Topology lane header now says
  `port2.20 · VLAN 20 on port2` (`parent` on lane interfaces). Tests `tests/test_port_topology.py`,
  `test_cov_routes.test_port_topology`; smoke `fwports`.
- Report write-ups (owner 2026-10-17, "from the report, remove the check list number, SR, FR, and SL. add in the
  62443 standard or best practice reference ... once per check all the firewalls and affected subnets/vlans or host
  placed into one finding per site; Fortinet for right now"): `app/writeup.py` (`SR_TITLES`, `NIST_BY_FR`, `CIS`
  topics, `CONCERN`, `FORTI` templates with `{placeholders}` filled from the finding's evidence by `forti_example`,
  `references(check, sr_text)`, `writeup(...)`); `generate_report.build_findings` prints the write-up block
  (`_writeup_block`) + `_affected_rows` per device; `_primary_reference` replaces SR / checklist columns in the
  priorities, coverage and check-selection tables; the FR x SL matrix is no longer added to the story; section
  headings without numbers. `explain()` returns `requirement.standards`, `concern`, `forti_example` (console drawer
  shows them, copy button). Workbook gains Concern / FortiOS example / references columns. Tests `tests/test_writeup.py`.
  Every `FORTIGATE_CONFIG_CHECKS` entry must have a `FORTI` template (test).
- Firewall selector on Network Topology / Lane Matrix (owner 2026-10-17, "multiple Firewalls in a site need a
  switch on the lanes to show the rules of the selected firewall"): `/topology/subnets` returns `firewalls`
  (id, name, switch, lane count) and per-firewall `policies` / `permit_policies` inside `separators[].through[]`;
  `ntFillFwSelect` fills `#nt-fw` / `#lm-fw` (hidden with < 2 firewalls); lanes `.nt-lane-fw` / `.nt-lane-other`,
  separators `data-fw=selected|other`, matrix cells `data-kind=other`. Test `test_policies_per_firewall_and_firewall_list`.

## In .33 (2026-10-18)

- Report layouts (owner 2026-10-18, from the sample "Technical Report" PDF; `layout=lrqa` = **LRQA compliance report**
  (default), `layout=public` = the previous report as **public compliance report** - `build_story_public`,
  `build_cover_public`, `build_findings_public`, `_draw_header_footer_public`, `_set_layout` switches the shared
  styles; route `layout` param, CLI `--layout`, Reports page `#rep-layout`): "use this report color, the cover
  page, table of content and finding sections as a template" -> "use the cover page wordmark; add the report
  details to the report download page; skip the figures and use the Fortinet config values or the application
  data. it should become the Compliance report"): `generate_report.py` - `_draw_cover` (navy panel, wordmark,
  Prepared For / Project / Author / Date), `_draw_header_footer` (wordmark, classification, page), `_ReportDoc`
  (TOC entries from style `IASCH1`, `multiBuild`), `build_contents` / `build_distribution` / `build_revisions` /
  `build_particulars` (scope from `_scope_networks` + firewall devices; `build_executive_summary` is its detail),
  `build_findings_summary` (4 Findings), `build_findings` (5 Analysis: `_analysis_entries` numbering, `_values_table`
  from `explain._FACTS`), `build_appendix_intro` / `build_standards`; TEAL palette, teal table headers. Model
  `ReportDetails` (`report_details`, migration `f8a9b0c1d2e3`), routes `GET/PUT /reports/details`
  (`_report_details_dict`), Reports page card *Report details* (`loadReportDetails`, `rdRow`, `putJson`); smoke
  `report_details` in `s_system`. Tests `tests/test_report_details.py`; report tests re-anchored.

- Lane Matrix page removed (owner 2026-10-18: "remove the lane matrix"): nav item, page, CSS, `loadLaneMatrix` /
  `renderLaneMatrix`, the `lm-fw` selector and the smoke section are gone; `/topology/subnets` keeps `separators`
  and the per-firewall policies for Network Topology. Firewall Ports table view: a row pins the policies of its
  port (`fp-table-row`, Enter / click; the pinned port's rows are marked).

## In .34 (2026-10-18)

- MFA coverage (owner 2026-10-18, "make sure the MFA findings cover local and FortiManager", recommended severities,
  FortiManager as a finding): `config_admin_no_two_factor` fires for every enabled local admin without two-factor /
  remote-auth (no more "only when MFA means exist" gate; high for `super_admin`; evidence `auth_source`, `mfa_kind`,
  `mfa_available`); `config_vpn_user_no_mfa` also counts local users of type ldap and LDAP servers named as group
  members (evidence `auth_sources`; RADIUS / TACACS+ members stay "covered"); new `config_fortimanager_admin_access`
  (info; low when `fmg` is a public address / name; `ref_key fortimanager-admin-access`; closes on a re-upload without
  FortiManager, otherwise acknowledge). 180 checks. Tests `tests/test_mfa_coverage.py`; batch A / B and e2e
  expectations updated.

## In .35 (2026-10-18)

- LRQA report Scope table: one firewall / network / input per line (`build_particulars._lines`, owner 2026-10-18).
- LRQA report: every 5 Analysis entry starts on a new page (owner 2026-10-18).
- Report details: *Client points of contact* and *Assessor team* as separate row lists (`rdRow('poc'|'dist')`, same
  `distribution` field with `side`); Distribution List heading "<client> - points of contact" (owner 2026-10-18).
  Bug fix: the card's Save called an undefined `who()` in .33 / .34 (console saves failed); now `rdWho()`.
- Audit 2026-10-18 fixes: remote-auth admins on LDAP groups are password-only; FortiManager names are reported, not
  judged; report-details rows sanitised (scalars, control chars, side) with 50 POCs + 50 assessors; console: row caps,
  focus kept after Enter on a Firewall Ports table row, egress review drawer refreshes after a save, Report details
  card cleared without a site, stale pin hidden before a reload; dead `external` lane code removed. Report: public
  roll-up cover / no TOC placeholder, no blank page before 4 Findings, `_RENDER_LOCK` around `render_pdf`, wrapped
  FortiOS blocks, quoted-vs-plain multi-interface values, per-site numbering in the roll-up (`num` / `analysis_num`).

## Since .35 (shipped in .36 and, with the audit fixes, .37 - 2026-10-19)

- `config_auto_firmware_upgrade` (owner 2026-10-19: "Judge auto-firmware-upgrade: enable on an OT firewall is a
  change-control concern"): low, SR 7.6 + 2-1 SPE 2, row 9.12; fires only on an explicit `set auto-firmware-upgrade
  enable` under `config system fortiguard`; evidence `upgrade_window` (days + hours), `delay`; evidence-page row;
  explain / writeup / CHECK_SECTIONS / reference / README / workbook. 181 checks. Test `tests/test_auto_firmware.py`.

- NTP source placement (owner 2026-10-19, "can the app confirm that the NTP is local based on the subnets on
  interfaces" -> "build it"): `_config_findings` places every custom NTP server as local (interface network, with the
  operator's level) / internal (static route, private) / external (public address or name) from `ctx.local_nets`,
  `routed_nets`, `iface_levels` (built at ingest); `config_ntp_fortiguard` now also fires for external custom servers
  (medium with a WAN leg, low without, high when no internal source and `server-mode` serves OT interfaces);
  `_extract_dns_ntp` returns `ntp_server_mode` / `ntp_server_interfaces`. Test `tests/test_ntp_source.py`.
- Uplinks (owner 2026-10-19): evidence rows "Uplink monitoring (system link-monitor)" and "Default routes (router static)"
  in the Availability section; info check `config_link_monitor_external` (every probe a public third-party host);
  `ctx.routed_nets` = (cidr, device) and `ctx.tunnel_interfaces` so an NTP server behind an IPsec route is placed as
  "remote site via <tunnel>" (kind `remote`, counts as inside). Test `tests/test_uplinks.py`.
- Wireless in OT (owner 2026-10-19, "wireless in the OT environment needs to be flagged and confirm no vlans are using
  weak passphrases or WEP"): `_hardening_findings(..., ctx=_cfg_ctx)` places each VAP (tunnel mode -> its `vap-switch`
  interface; bridge mode -> `vlanid` -> the VLAN sub-interface) and reads the operator's level: new
  `config_wireless_in_ot` (high); `config_wireless_weak_security` is high for open / WEP / WPA1 in OT and low for a
  PSK on an OT SSID (passphrases are `ENC`, strength unreadable); `config_wireless_not_isolated` also matches
  `vap-switch`; evidence section "Wireless (row 2.5)" (controller state, SSIDs, managed APs, WIDS profile); an SSID
  not broadcast (controller off / no radio assignment / no AP, FortiWiFi `FWF…` profile = built-in radio) is info
  "defined but not broadcast". Test `tests/test_wireless_ot.py`.
- FortiLink-managed FortiSwitches (owner 2026-10-19, "build it, FortiLink-managed first"): `app/parsers/fortiswitch_parser.py`
  `ingest_fortilink_switches` (called from the FortiGate ingest; `stats["fortilink"]`) writes SwitchInterface rows
  (`source_file` `fortilink:<fw>`, new columns `port_security_policy`, `admin_status`, `uplink`; migration
  `b4c5d6e7f8a9`) and SwitchVlan rows (level from the FortiGate VLAN interface, source `firewall_propagated`); reviews
  `review_switch_port_nac` (`switch_port_no_nac`) and `review_switch_unused_ports` (`switch_unused_port_enabled`);
  Firewall Ports shows `fortiswitches` under the FortiLink port. Standalone FortiSwitchOS configs:
  `POST /ingest/switch?vendor_hint=fortinet` (`switch_parser.parse_fortinet_switch_config`, config type
  `fortinet_running_config`, rows `source_file` `fortiswitch:<file>`; `switch_hardening` reads FortiOS-style SNMP
  communities and `allowaccess telnet`); the two port reviews cover both sources (`forti%:%`). 185 checks. Tests
  `tests/test_fortiswitch.py`, `test_cov_alert_engine.test_review_fortiswitch_ports`.
- IPsec selectors (owner 2026-10-19, "tighten the Access review page with the selectors; add the resilience evidence"):
  `forti_config_parser.extract_tunnels` (phase1 peer / WAN / `monitor` backup / phase2 `src-subnet` <-> `dst-subnet`,
  `system ipsec-aggregate` members unioned) stored as `FirewallInterface.tunnel_info` (JSON; migration `b4c5d6e7f8a9`);
  `access_paths.tunnel_selector_map` + `_narrow_by_selectors` intersect a rule's src / dst with the remote selectors of
  the tunnel interface it names (ContextVar `_TUNNEL_SELECTORS` set in `_enumerate`), rows flagged `tunnel_selector`;
  evidence rows "Site-to-site IPsec tunnels" and "Redundant VPN tunnels" (backup `monitor`, same peer over two WAN legs,
  aggregates). Test `tests/test_tunnel_selectors.py`.
- Address objects tighten checks (owner 2026-10-19, "to confirm the app is using this data to tighten and clarify
  checks"): `config_local_in_permits_all` resolves `srcaddr` (`sources_resolved`, `external_sources`, `wide_sources`;
  high when an outside interface takes any / external sources); dial-up tunnels get a selector from the client pool
  (`ipv4-start-ip`-`end-ip`, remote) and the resolved `ipv4-split-include` (local) - `tunnel_selector_map` returns
  (remote, local) and the local side narrows the other end for dynamic tunnels only; policies on a dial-up tunnel
  contribute `groups` / `users` to the VPN MFA check (`ctx.dialup_tunnels`); hosts created from /32 objects take the
  object name as hostname and `device_classification.classify_object_name` as a suggestion (source `object_name`,
  role `switch` / `ap`); evidence section "Remote access and user groups (row 4.3)" (who authenticates each group).
  Test `tests/test_object_data.py`.
- Address-object types (2026-10-19): `_addr_objects(parsed)` completes `type interface-subnet` objects (static subnet
  as written, `0.0.0.0` form = the named interface's network); `*.name` in a plain `fqdn` object is a wildcard
  (`wildcard-fqdn:` token, high); `type dynamic` (EMS tag) resolves to `dynamic:<name>` (uncertain, not missing);
  object names never classify a public address. Test `tests/test_address_types.py`.
- Source placement (owner 2026-10-19, "IP address reached through tunnels (ipsec, vpn, etc) should be considered
  remote"): `_place_source(token, ctx)` -> local / internal / wide / remote / external / unplaced (`outside` =
  remote, external, unplaced); `ctx.tunnel_nets` from `_tunnel_nets(parsed)` (phase 2 remote selectors, dial-up
  pools, SSL-VPN pools). Used by `config_local_in_permits_all` (`remote_sources`, `unplaced_sources`,
  `source_places`). `_saml_idps(parsed)`: FortiTrust ID (`fortitrustid.forticloud.com`) = cloud MFA in the
  user-group evidence, the new "SAML identity providers" row and the VPN MFA finding's `remote_sources`.

## In .38 (2026-10-24 .. 2026-11-09)

- Audit checklist report (owner 2026-10-24, "a program that takes the ISA62443_master_audit_check_list.xlsx file as an import
  and creates a report ... CSV export besides a pdf"): `app/audit_checklist.py` (`parse_workbook`, `is_finding`, `select_rows`
  scope findings / assessed / all, `order_rows`, `domain_summary`, `report_data`, `to_csv`, `summary_json`),
  `generate_audit_report.py` (LRQA layout via `generate_report` helpers; `_draw_cover` takes `title_lines`), route
  `POST /reports/audit-checklist` (`format` pdf / csv / json, `scope`, `order`, optional `site_id` -> Report details on the
  cover), Reports page card *Audit checklist report* (`auditChecklist`, `renderAuditPreview`; smoke `audit_checklist`).
  One report finding per checklist row: Check title = title, Audit check = details, Domain, the auditor's Finding /
  Observation, Evidence Reviewed, Recommendation (+ status, maturity, severity, owner, target date). Nothing stored.
  Tests `tests/test_audit_checklist.py`. The owner's workbook lives in `../Checklist/` (not in the repo).
  Second ask (same day, "the program needs to ask for client POC ... LRQA consultant ... author ... Prepared for ... date of
  report"): CLI `prompt_details` (TTY prompts; flags `--client --author --date --poc --consultant --no-prompt`), route form field
  `details` (JSON; `clean_details` / `merge_details` over the site's Report details), card fields Prepared for / Author / Date /
  Client POC rows / LRQA consultant rows (`acPrefill`, `acDetails`; `rdRow(..., prefix)`), report `build_distribution`
  ("LRQA consultants") / `build_revisions`, `report_date` on the cover.
  2026-10-25: `ui/lrqa_logo.png` (owner's LRQA logo) on the audit report cover (`_draw_cover` `logo`; `generate_audit_report.LOGO`);
  `make-dist.sh` ships `generate_audit_report.py`.

## Since .38 (2026-11-09, unreleased)

- Owner batch ("build 1,3 and AV a with the plus items"; tracker "Owner batch 2026-11-09"): address groups with
  `exclude enable` / `exclude-member` resolve to members minus the exclusions (`_group_exclusions`,
  `_subtract_addresses`, `_groups_with_exclusions`; rule-text note "… group X excludes Y"; `stats["addrgrp_exclusions"]`);
  `config_permit_any_any_any` is high when service is ALL and the source interface is a remote-access tunnel
  (dial-up IPsec incl. `set usrgrp`, `ssl.<vdom>`; evidence `from_remote_access`, `remote_access_interfaces`, `identity`);
  `config_av_missing_on_file_policy` is info when every destination interface is labelled L0-L3 (`destination_in_ot`,
  `dst_level`); `SwitchInterface.port_security_mode` (`802.1x` / `802.1x-mab` / `open-auth`; migration `c5d6e7f8a9b0`,
  head) read from the FortiLink 802.1X policy (`fortiswitch_parser.policy_mode`) and FortiSwitchOS `security-mode` +
  `config port-security`; `review_switch_port_nac` counts open-auth ports as unprotected (`open_auth_ports`,
  `no_policy_ports`, `mab_ports`); `access_paths.tunnel_selector_map` keys FortiOS zones whose members are all
  tunnel interfaces (union of remote selectors, no local bound; mixed zones not); `config_local_in_permits_all` judged
  per VDOM table (ctx `vdom_views`, `ref_key local-in:<vdom>/<id>`, evidence `vdom`). Test `tests/test_owner_batch_1109.py`.
- LRQA logo (owner 2026-11-10, "use this logo in the LRQA report in place of the IASC Monitor"): `generate_report.LOGO`
  (`ui/lrqa_logo.png`) / `_logo_path` on the LRQA cover and in every footer; the wordmark is the fallback; public layout untouched.
- Branches (owner 2026-11-10): `main` = private LRQA-branded version; `public` = main plus ONE commit "Public branch: report
  branding removed" (public layout only, no logo file, audit checklist report kept unbranded as "Assessor team"; tracker
  "Public branch - 2026-11-10"). Until the owner says otherwise only the report branding differs: land every change on
  `main`, then `git checkout public && git merge main`; never commit features on `public`. **This file is the `public`
  branch copy** - the branding paragraphs above describe `main`.

## Open / not started (owner hasn't asked)

- **Evidence matrix gap analysis (2026-10-15)**: `../project-docs/evidence-matrix-gap-analysis.md` compares the
  owner's `Checklist/ISA62443_Evidence_Automation_Matrix.xlsx` (149 master checks) with the 156 checks: 21
  candidate new checks in three batches (A = 13 config-only, B = MFA / IPsec crypto / DoS / SIS / wireless,
  C = PCAP: transient-device OUIs, default credentials, weak TLS, version leaks) and clarifications to existing
  checks. Batches A, B and C implemented 2026-10-15 (see "Since .29").

- A-01 / H-01 (deferred).
- **On hold (owner, 2026-10-15): CIS FortiGate Benchmark work** - asked for (a) a *CIS benchmark findings only*
  option on the Findings page, (b) the config checks updated / extended against the CIS FortiGate Benchmark,
  (c) a CIS FortiGate benchmark findings checklist section on Reports & Diagnostics; then "place the CIS on hold
  also". Proposed (not started): shipped mapping file `app/frameworks/cis_fortigate.csv` -> `framework_controls`
  table + `POST /frameworks/import`; `framework=` filter and CIS id badges on findings; Reports card with one row
  per recommendation (FINDINGS / PASS / NOT EVALUATED / not covered); candidate new checks (banners, strong-crypto /
  static TLS keys, SNMPv3-only + trusted hosts, HA monitor / reserved mgmt interface, AV push / outbreak /
  grayware, botnet DNS filter, SSL-VPN TLS versions / certificate, event logging / encrypted log transport) for
  the owner to pick. Open questions: benchmark edition (FortiOS 7.0.x v1.3.0 vs 7.4.x), the recommendation list
  (licensed PDF - owner to provide in ../project-docs/), console only vs PDF section.
- **On hold (owner thinking, 2026-10-14): framework-scoped reports and the mapping update method.**
  Owner wants a compliance report limited to one framework's findings, each labelled with that
  framework's control number (CIS FortiGate recommendation, IEC 62443-2-1 element, NIST ...), and
  an upload function for the check -> control mappings ("concerns"). Agreed design so far: a
  per-framework mapping table (framework, version, check_name, control_id, title, section) loaded
  from uploaded CSV / shipped defaults, validated against the catalogue, replace-per-framework
  with old versions kept; `framework=` on the PDF / CLI; group-by-framework on Checks in the
  report. Not started: the owner is deciding the update / refresh method. Checks themselves stay
  code (an upload maps existing checks only).
- **On hold (owner thinking, 2026-10-12): firmware version checking.** The `#config-version` /
  `#buildno` header is skipped as a comment, so `FirewallDevice.firmware_version` is never set and
  row 5.6 has no check. Options discussed: show the version; branch past end of support + "update
  available" from an offline bundle file (lifecycle dates, latest patch); Fortinet PSIRT CSAF matching
  (RSS `filestore.fortinet.com/fortiguard/rss/ir.xml` -> csaf JSON), offline bundle recommended.
- MP-25 remainders: SNAT pool far-side placement, routing-switch OR hiding a firewall policy,
  one-host flat evidence, `subnet_level` order dependence, per-firewall-set roll-up of chain findings.
- Inventory import item 6: mapping device-type *values* (e.g. "PLC – Siemens S7-1500" -> `plc`).
- Optional sample-data load at installation.
- iptoasn file not shipped (supported via `IACS_IP2ASN_FILE`).
- Zip-format packages (only tar.gz produced so far).
- Not yet re-run on real data: `rule_dns_external` on the owner's real config
  (policy 306 DNS_Services should give one finding, high once vlan_20/22 are labelled OT).
