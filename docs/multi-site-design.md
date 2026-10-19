# Multi-site support — design

Status: approved 2026-10-01 · All phases implemented (1-4; see README "Sites") · Phase 1: migration c0d1e2f3a4b5, app/sites.py

Phase 2 part A implemented 2026-10-02: migration e1f2a3b4c5d6 (per-site unique indexes: hosts, firewalls, firewall_devices, baselines incl. one active per site, switch tables, firewall_zones, findings open source_ref, fortiana_events dedup_hash, attestations current row); ingest get-or-create scoped to the upload site (`app.sites.scope_site_id`); per-site routes (`site`/`site_id`, derived only when exactly one site exists, else 422; cross-site references 422); `/reviews/run` without site reviews every site in turn (`sites` map); scheduler runs per site; `GET /attestation/current`; report `all_sites=true` roll-up.

Phase 2 part B implemented 2026-10-02: per-site analysis scope (`app/parsers/site_scope.py`: `analysis_site(db, site_id)` / `@site_scoped` add `with_loader_criteria` on every site-scoped table, and on child tables via their parent, for each ORM statement of a run); reviews, auto-resolve, review-run lock, reachability, topology, shadow, cross-FW, topology diff, last_matched and classification run inside one site; `evaluate_event` uses `ev.site_id`; cross-site links raise `CrossSiteError` (routes answer 422).

Phase 3 implemented 2026-10-02: migration f1a2b3c4d5e6 (`site_devices`, `unmapped_log_events`); `app/site_devices.py` (registry, `resolve` serial-then-name, per-line `LogRouter`, replay, retention); firewall config uploads auto-register their hostname (`site_devices` / `site_device_conflicts` in the response, never moved between sites); every log route routes each line to its device's site, unknown devices are held (no checks) and deduplicated, `?site=` maps unknown devices only (`site_conflicts`, `new_mappings`, per-site `routed` in `routing`), lines without a device identity go to `?site` else the queue (never Default); `/site-devices` CRUD (POST/PATCH replay held lines; remap = new lines only; DELETE gated), `GET /site-devices/unmapped`, `POST /site-devices/unmapped/discard`, `POST /site-devices/unmapped/purge`; daily retention job (`IACS_UNMAPPED_RETENTION_DAYS`, default 30: replayed/discarded lines and pending lines older than the period); `/sites` counts `devices` and `unmapped_pending`; console "Devices" page with pending-line badge, optional "map unknown devices to" site on log uploads with a routing summary.

Phase 4 implemented 2026-10-02 (no migration): `GET /sites/rollup` (read-only, grouped queries: counts, open findings by severity, last review run (per process), last config/PCAP upload, active baseline, attestation current/overdue, global unmapped count, totals); console "Sites overview" page (card per site, open-findings click-through sets the site selector, per-site PDF link); per-site PDF cover shows site name and code and only that site's data, `all_sites=true` = summary table + one section per site; retention unchanged from phase 3 (held lines only; findings/events are never auto-deleted); README and tracker (F-20). Known limitations: stored data is not moved on remap/rename, `unmapped_pending` is global, `last_review_at` resets on restart.

B-11 implemented 2026-10-04: device routing conflicts, see "B-11: device routing conflicts" below (migration c4d5e6f7a8b9).

B-12 implemented 2026-10-04: HA clusters in the device registry, see "B-12: HA clusters" below (migration d5e6f7a8b9c0).

## Requirements (owner)
- Sites are **isolated** from each other for analysis purposes.
- The site is **defined at upload time** (no inference).
- Device names are **associated with a site**.
- Syslog from **unknown devices** needs a **map-to-site** function.
- Remapping a device affects new log lines only; stored events/findings are not moved (assumed; revisit if needed).

## Data model
- `sites` (id, name unique, code unique, description, created_at). Migration creates **Default** and assigns all existing data to it.
- `site_id` (FK → sites, NOT NULL after backfill, indexed) on root objects: Firewall, FirewallDevice, Host, PcapCapture, FortiAnalyzerEvent, Baseline, Attestation, Finding, SwitchInterface, SwitchVlan, MacTableEntry (and any other root table). Children (FirewallRule, NatRule, FirewallInterface, FirewallZone, NetworkSession, ProtocolDetail, HostAddressHistory, ApprovedComms/Hosts) inherit via parent; denormalise only where queries need it.
- `site_devices` (site_id, device_name normalised, vendor, source config_upload|manual, created_at; B-12: is_ha, ha_mode, ha_group_name, ha_group_id) with its serials in `site_device_serials` (one per unit, globally unique). Lookup by any member serial first, then name. Same name at two sites allowed only with distinct serials.
- `unmapped_log_events` (raw line, device key, serial, vendor, source route, received_at, dedup_hash, upload ref, status pending|replayed|discarded).

## Identity scoped by site (isolation)
Host IP/MAC uniqueness, session 5-tuple, firewall names, finding dedup (source_ref includes site), baselines (one active per site), attestations (checklist × baseline × site).

## Uploads
- Non-log uploads (configs, PCAP, ARP, switch, MAC table, baselines, inventory, attestation): `site` **required** (name or id); 422 if missing/unknown.
- Firewall config upload auto-registers its hostname/serial in `site_devices`.
- Log uploads (`/ingest/syslog`, `/ingest/forti-*`): routed per line via `site_devices`; unknown → `unmapped_log_events` (no checks run); optional `?site=` maps *unknown* devices in that file to the site, never overrides an existing mapping; mismatches are held as `site_mismatch` conflicts and counted as `site_conflicts` (B-11).

## Analysis
Every review, auto-resolve, review-run lock, reachability, topology, shadow, cross-FW, topology diff, last_matched, classification and report runs within one site. Cross-site views are read-only roll-ups only.

Scope mechanics and their limits (C-18): `analysis_site` installs an ORM loader criterion on every `SiteScoped` model, so ORM queries are filtered automatically. Three things bypass it and must carry the site explicitly: Core statements (`insert/update/delete(X.__table__)`, used only in `insert_host_row`, which takes `site_id`), `Session.get()` of an object already in the identity map (the scheduler therefore `expunge_all()`s between site runs; code that follows a foreign key from a scoped row uses `_iface_in_scope` / `_fw_in_scope`), and rows created without `site_id` (filled at flush from their parent row; when the parent's site differs from the bound site a warning names both - that is a scoping bug upstream, the row follows its parent).

## API / UI
- `/sites` CRUD; `site_id` filter on every list endpoint; findings summary per site.
- `/site-devices` CRUD, `GET /site-devices/unmapped`, `POST /site-devices` maps and **replays** held lines.
- Console: global site selector; site required on every upload form; "Unmapped devices" page with pending-line badge.
- Retention purge of held lines (default 30 days).

## Phases
1. Sites table, `site_id` on roots, Default backfill, required `site` on non-log uploads, list filters, console site selector.
2. Site-scoped identity and per-site analysis/reviews/baselines/attestations/reports.
3. Device registry, syslog routing, unmapped queue, mapping + replay, UI page.
4. Retention, roll-up dashboard, per-site PDF, README/tracker.

## B-11: device routing conflicts
Owner decision (2026-10-04): **never guess a site for a conflicting line** - hold it and let the user choose; a resolution replays the held lines and applies to new lines; stored data is never moved.

Routing per line (`app/site_devices.py`, `LogRouter._decide`), in order:
1. **Serial registered** (any device) → that device (serial wins, even under another name).
2. **Name registered, line carries a serial**:
   - the name's rows are at one site and one of them has **no serial** → *serial binding*: the serial is recorded on that row (`serial_source='first_seen'`, `serial_bound_at`) and the line routes normally;
   - otherwise (the name has another serial) → held as **`serial_conflict`** (snapshot of the registered row; none when the name is at several sites).
3. **Name registered, no serial** → the name's site if unique (name-only vendors keep routing by name), else held as `unmapped` (ambiguous, unchanged).
4. A device found in 1-3 while the upload names `?site=X` and the device is registered elsewhere → held as **`site_mismatch`** (was: routed to the registered site and only counted).
5. Unknown device → `?site` registers it there, else held as `unmapped` (unchanged). Lines without identity → `?site`, else held (unchanged).

Data model (migration c4d5e6f7a8b9, idempotent, no backfill):
- `site_devices.serial_source` (`config_upload` | `manual` | `first_seen` | `conflict_resolution`), `serial_bound_at`.
- `unmapped_log_events.kind` (`unmapped` | `serial_conflict` | `site_mismatch`, default `unmapped`), `registered_device_id`, `registered_site_id`, `registered_serial`, `map_site_id` (snapshots, no FKs, so held lines survive device / site deletion); index (`kind`, `status`). Conflicts share the queue table so retention, dedup and replay stay one mechanism; every queue function filters by kind (mapping a device replays `unmapped` lines only; `/site-devices/unmapped`, `unmapped_pending` and the unmapped discard ignore conflicts).
- `device_conflict_resolutions` (audit: `resolved_at`, `action`, `kind`, `device_key`, `serial`, registered device / site / serial before the change, `target_site_id`, `device_id`, `lines`, `events_created`, `findings_created`, optional `resolved_by`).
- Held-line **dedup key** = sha1(`held|<resolved device key incl. ?device_name fallback>|<serial>|<line hash>`): the same identity-less line uploaded with `device_name=fwA` then `fwB` is held once per device (previously the second was dropped as a duplicate → data loss on mapping).
- Mapping a device (`replay_pending`) applies the same rules to its held lines: the first serial seen binds a serial-less device; lines with another unregistered serial become `serial_conflict`.

API:
- `GET /site-devices/conflicts` - groups by (`device_key`, `kind`, `serial`): count, first/last seen, registered device (live row, else snapshot; candidates when ambiguous), line serial, vendor, requested site(s), sample line, `different_device_allowed` + hint; `detail` adds lines; `site_id` keeps groups whose registered or requested site it is; `kind` filter.
- `POST /site-devices/conflicts/resolve` `{device_key, kind, serial?, action, site?, device_name?, device_id?, resolved_by?}`:
  - `same_device` - the registered device sent them (replaced unit): serial_conflict updates its serial (`serial_source='conflict_resolution'`; 409 when the serial is registered to another device meanwhile); site_mismatch keeps it. Lines replayed into the registered device's **current** site (so "device moved" = PATCH remap, then same_device).
  - `different_device` + `site` - registers a new device (`device_name` or the key, the line's serial) at that site and replays there; future lines route there by serial (e.g. the HA peer of a FortiGate pair, same site). Refused (409) when the lines cannot be told apart from the registered device - always the case for site_mismatch (same identity) - and when `register()` reports a conflict.
  - `discard` - gated by `IACS_ENABLE_DELETE` like the other discards.
  - Replays go through `_replay_rows` (normal ingest path: stored, deduplicated, real-time checks and rule hits in the chosen site). Each call writes one `device_conflict_resolutions` row. `GET /site-devices/conflicts/resolutions` lists them.
- `/sites` counts and `/sites/rollup` carry `conflicts_pending` (global, like `unmapped_pending`); routing summaries carry `conflicts`, `conflict_duplicates`, `serial_conflicts`, `site_conflicts`, `serial_bindings`; ingest stats count `conflicts` separately from `unmapped`; `/ingest/forti-event` answers `status: "conflict"`.

Console (Devices page): a **Conflicts** list beside "Unmapped devices" (name, kind, both serials, registered site, requested site, counts, first/last seen, sample line) with *Same device - replaced unit* / *Different device - pick site* (disabled with the reason when not applicable) / *Discard*; each opens an in-row confirmation (site picker and optional name for different_device; Escape / Cancel returns focus; no `confirm()`), then shows the replay summary. The nav badge counts unmapped + conflict lines. upload.html shows the held-conflict count.

Source-IP pinning (considered, not built): uploaded files carry no transport source IP. The only address-like field is the syslog header host, which the ASA / pfSense / PAN-OS parsers already use as the device name (a device that logs its IP there is registered under that IP), so a separate `source_ip` tiebreak would add nothing reliable. Two name-only devices with the same name at two sites therefore remain indistinguishable (held as ambiguous / site_mismatch).

## B-12: HA clusters
Owner decision (2026-10-04, "do it"): an FGCP HA cluster is **one device** in the registry. Its units share the hostname but every log line carries the logging unit's serial (`devid`); with one serial per device the second unit's lines became serial conflicts and the cluster looked like two devices.

Data model (migration d5e6f7a8b9c0, idempotent; fresh installs - an existing `site_devices.serial` is copied over before the column is dropped):
- `site_device_serials` (`device_id` FK ON DELETE CASCADE, `serial` unique globally, `source` config_upload | first_seen | manual | ha_evidence | conflict_resolution, `added_at`, `last_seen_at`, `last_role` primary | secondary | NULL). `site_devices.serial`, `serial_source`, `serial_bound_at` are gone; the model derives them from the first member (the B-11 API fields stay).
- `site_devices.is_ha`, `ha_mode` (a-p | a-a | NULL), `ha_group_name`, `ha_group_id`. Max members `IACS_HA_MAX_MEMBERS` (default 4, the FGCP limit).
- Routing by ANY member serial → same device → same site. A unit belongs to one device, so to one site; remapping a cluster moves all its members.

HA detection: a FortiGate config upload with `config system ha` (also inside `config global`) sets the registered device's HA state (per site, per hostname - the row the upload registered): `set mode a-p|a-a` → HA with `group-name` / `group-id`; `standalone` or no `mode` → not HA. No block → unchanged. Pending conflicts of the device are re-tagged to follow (`serial_conflict` ↔ `ha_candidate`).

Member binding when a line carries an unknown serial under a registered name (`LogRouter._decide`):
- device without any serial → B-11 first-seen binding (HA or not);
- standalone device → B-11 `serial_conflict` (unchanged);
- HA device → held as **`ha_candidate`** (new kind) unless the serial is already a member: a member is added automatically on **evidence** - an FGCP HA event log (`type=event subtype=ha`, logid **0108037894** "Virtual cluster member joined" or **0108037892** "Virtual cluster member state moved") written by a **known member** (`devid`) whose `sn` names another unit, `ha_group` equal to the configured `group-id` when both are known, the unit registered nowhere and the cluster not full - or by manual pre-registration (`POST /site-devices/{id}/serials`). Evidence is applied when the HA log is routed (also on replay and on duplicates, so re-uploading the log after the config marked the device HA works); the member is added (`ha_evidence`, audit row action `ha_evidence`, `resolved_by` "auto: HA event log") and the lines held for that serial (its `ha_candidate` / `serial_conflict` rows and unmapped rows under the device name) are replayed into the device's site at once, whether they arrived earlier in the same file or in an earlier upload; later lines of the upload route normally. Held lines whose upload named another site (`map_site_id`) are never auto-replayed (no cross-site move); a serial owned by another device is never taken over.
- Field sources: Fortinet FortiOS Log Message Reference 37892 / 37894 (docs.fortinet.com), Fortinet sample HA logs (`logid="0108037894" ... ha_group=0 sn="FG2K5E3916900286"`, `logid="0108037892" ... ha_role="master" vcluster_state="work" hostname=... sn=...`), LogRhythm's FortiGate HA mapping (`sn` = serial of the unit that joined, `ha_group` = HA group ID); URLs in `app/site_devices.py`. Gap: the peer field of 0108037893 "member dead" and of heartbeat-device logs could not be confirmed (the reference pages render client-side), so they are not evidence.

API: device responses add `members` [`serial`, `source`, `added_at`, `last_seen_at`, `last_role`], `is_ha`, `ha_mode`, `ha_group_name`, `ha_group_id`, `max_members`. `POST /site-devices/{id}/serials {serial}` (201 / 200 already a member; 409 registered elsewhere, standalone with a serial, or full; replays held lines; audit action `manual_member`). `DELETE /site-devices/{id}/serials/{serial}` (IACS_ENABLE_DELETE). `PATCH serial` replaces the only serial (409 for a multi-member cluster). Conflicts: kind `ha_candidate`; groups carry `add_ha_member_allowed`, `add_ha_member_needs_mark_ha`, hint; resolve action **`add_ha_member`** (409 unless the device is HA or `mark_ha: true` confirms marking it HA; 409 when full or the serial is registered elsewhere) replays the held lines into the device's site. Routing summaries add `ha_candidates` and `ha_members`.

Failover finding: check `ha_failover` (real_time, low, SR 7.1/7.2, checklist 7.4) in the real-time checks (`track_member_activity`). Every stored line updates its serial's `last_seen_at` (event time). For an **a-p** device the active member is the one logging forwarded traffic / UTM (`subtype=local` excluded - every unit logs its own local traffic) or named primary by a 0108037892 log (`ha_role` master/primary; slave/secondary just sets `secondary`). A change from the member last seen active - not for a line older than that member's last line (out-of-order uploads) - raises one finding per device, new primary and hour (dedup `site_device_id`, `to_serial`, `window_hour`), in the device's (= event's) site. First observation sets the baseline silently; a-a and unknown modes never raise it. Like every real-time finding it is never auto-closed - it stays as the audit record until acknowledged / closed.

Console (Devices page): HA devices show an *HA mode · group* badge and the member list (serial, active marker, source, last seen) with **Add member serial** (Enter / button → in-row confirmation naming member n of max and the site; Escape / Cancel returns focus; then the result). HA member candidates list **Add as HA member** first (serial conflicts offer it last, marking the device HA after the confirmation).

