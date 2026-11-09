# Access-path review & permissive-policy reporting — design

Status: Phases 1-4 implemented 2026-10-04: enumeration (app/parsers/access_paths.py), traffic overlay, Access Review screen (ui/index.html), access_path_tag storage + POST /access-paths/classify, findings sync (app/parsers/access_path_findings.py) and the report section in generate_report.py.
reachability engine (`app/parsers/reachability.py`), firewall topology
(`app/parsers/topology_manager.py`), and the findings/report pipeline.

## Goal (owner)

> Map communication allowed from higher layers (IT, DMZ, L5, L4) to lower
> levels, over a single firewall or a chain of firewalls, purely from
> firewall access rules (no PCAP required). Overlay PCAP where available to
> show which of those allowed communications are actually occurring. Display
> every path in a review screen so the operator can **select which lines to
> report on** and classify rules as permissive or as `rule_it_ot_bypass`,
> and print the selection.

Upward (lower→higher) flow is in scope too — see "Direction model".

## What already exists (reused, not rebuilt)

- **Config-only path engine, multi-firewall.** `compute_reachability` /
  `compute_path` enumerate higher↔lower crossings from access rules alone and
  chain across firewalls via `upstream_chain` (walks `upstream_firewall_id`).
  Each hop carries `enforcement_points` and the exact `matching_rule`
  (policy id, name, src/dst, service, action). No new verdict logic needed.
- **Permissive/bypass detectors.** `review_rule_it_ot_bypass`,
  `config_permit_any_any_any`, `rule_cleartext_protocol`, `rule_mgmt_protocol`,
  `rule_mgmt_wrong_zone`, `check_ot_internet_egress`,
  `review_ns_remote_access_bypass` — each already names the policy.
- **Observed traffic.** `NetworkSession` (from PCAP), per-rule hit count /
  `last_matched`, and `canonical_flow` (client/server by well-known port).
- **Compliance PDF** (`generate_report.py`) and the findings lifecycle.

Missing, and built here: (1) a single enumeration of **all** permitted paths
with their permitting policy and direction-aware flags; (2) the PCAP overlay
onto that list; (3) a review screen to select/classify lines; (4) a report
section driven by the selection.

## Direction model (both directions, direction-aware)

Purdue levels: L5/L4 = IT/enterprise, L3.5 = industrial DMZ, L3→L0 = OT.
"Higher→lower" (downhill) = source level > destination level. Enumeration
covers **both** directions; upward is not inherently bad (historians, OPC,
telemetry, syslog legitimately flow up), so upward rows are classified, not
condemned, and lean on the approved-conduit baseline + PCAP overlay.

Per-path flags (a row may carry several):

| Flag | Direction | Meaning |
|---|---|---|
| `it_ot_bypass` | down | IT-side (L3 and up, including the DMZ) reaching L0/L1, or L4/L5 reaching L2, in one routed session. Passing through DMZ firewalls does **not** exempt it; only composed rows (a real session break on a DMZ host) are exempt |
| `ot_egress_external` | up / out | OT zone → IT / internet / external scope |
| `ot_upward_skip` | up | the upward mirror of `it_ot_bypass` (G-02): deep OT (L0/L1) reaching L3 and up (incl. the DMZ), or L2 reaching L4/L5, in one routed session - passing every boundary's firewall does not end it; also any uphill row with fewer enforcement hops than Purdue steps. Raised as `chain_ot_upward_skip` (medium, high when seen) |
| `conduit_through_dmz` | composed | up-leg + down-leg joined through a dual-homed/DMZ host = end-to-end IT↔OT conduit |
| `pivot_outside_dmz` | composed | as `conduit_through_dmz`, but the joining host is not at L3.5 (e.g. an L3 server): the session breaks on a host outside the DMZ |
| `dmz_bypass` | down / up | the site has a DMZ (L3.5) but the row joins L4/L5 (or a VPN pool) and L3 directly. Raised as `dmz_bypass`: IT → L3 medium, high for remote-access protocols, any service, permit-any, a VPN source or seen traffic; L3 → IT low. Exceptions are classified in Access Review |
| `internet_egress` | up / out | an OT host (L0-L3; L3 counts as OT) may reach a public / any destination. Raised as `path_ot_internet_egress` (row 3.7): L0/L1 critical, L2 high, L3 medium, one step up when seen |
| `nat_published` | any | a firewall VIP (destination NAT / port forward) publishes the destination; the row's `nat` names the VIP (external → mapped) |
| `source_nat` | any | a firewall translates the source on the way; the row keeps the original source, `nat` names the translated address. Into L0-L3 from above it is raised as `nat_hides_source_into_ot` (medium) |
| `declared_hop` | composed | the two legs are joined by an operator-declared hop (gateway → jump host) inside one DMZ segment |
| `permit_any` | any | any-source, any-dest, or any-service |
| `tunnel_selector` | any | the row crosses an IPsec tunnel interface (or a FortiOS zone whose members are all tunnel interfaces with selectors): its source / destination is the policy intersected with the tunnel's selectors - the phase 2 remote subnets of a site-to-site tunnel, or the client pool and the split-include networks of a dial-up tunnel (`policy_scope` keeps the wider policy text); the flag is set only when a side was actually narrowed; a side of another address family than the selectors is left as it is; a policy that permits nothing inside the selectors makes no row |
| `direction_unverified` | any | no interface, zone or classified host behind the policy carries a Purdue level, so the firewall applied it in both directions by default; the row may be the reverse of reality. The envelope's `unlabelled_firewalls` names the firewall and its unlabelled interfaces (D-11) |
| `cleartext_protocol` | any | cleartext protocol (FTP/Telnet/SMTP/TFTP/HTTP/POP3/IMAP/SNMP v1/2…) across a zone boundary - the `rule_cleartext_protocol` port list |
| `mgmt_protocol` | any | management protocol (SSH/Telnet/RDP/VNC/WinRM/SNMP/8443…) across a zone boundary - the `rule_mgmt_protocol` port list; Telnet / SNMP v1/v2c carry both flags (was one `insecure_protocol` flag until 2026-10-12) |
| `industrial_proto_out_of_zone` | any | Modbus/DNP3/S7/EtherNet-IP permitted outside its expected zone |

### Chain-aware findings (D-05)

The rule twins (`rule_it_ot_bypass`, `rule_mgmt_wrong_zone`) judge one policy
on one firewall; a chain of firewalls that each cross adjacent levels is
invisible to them. `app/parsers/chain_findings.py` runs on the access-path
rows during every review run and raises, for rows whose chain spans ≥ 2
firewalls, `chain_it_ot_bypass` (row flagged `it_ot_bypass`; high for a deep-OT
destination, medium for L2, one step up when seen in capture) and
`chain_mgmt_wrong_zone` (IT-side → OT over SSH/Telnet/HTTPS/RDP/HTTP/SNMP;
medium, high when seen, DMZ-only source one step lower; not raised when the
source is inside the declared management networks or the first firewall's
source zone is declared a management zone - docs/management-networks.md). Each bypassing
sub-chain is its own finding (fixing the L4 policy does not fix L3 → L1), except
a tail whose source scope is one host known to live at another level (the
downstream policies merely name that host as an allowed source): that is the
longer chain's finding. A chain ending short of its destination host's level
shows how far the permits reach (e.g. "7 of 8 firewalls permit").
Findings dedup on the row's tag key, carry the whole chain in evidence, skip
rows flagged `direction_unverified`, and auto-resolve when the row disappears
or the reviewer classifies it `reviewed_ok` / `exception`. The enumeration is
computed once per run and shared with the classification sync.

### Effective scopes and first match (G-04)

A row's `src.scope` / `dst.scope` is what the WHOLE chain lets through - the
intersection of every policy's source / destination - not the first / last
policy's own text (kept as `policy_scope` when broader). `permit_any` is judged
on that effective traffic, so an outer ANY rule contained by a narrow inner
rule no longer marks the row. Policies evaluated before a firewall's terminal
permit are candidates too, and when several policy combinations let exactly
the same traffic through the same firewalls, only the first match per
firewall is kept; the others are listed in `shadowed_by_first_match`.

### Grouping and VPN chains

Chain findings (bypass, upward skip, management, dead end) are raised **once
per policy chain and level pair**, not per expanded row: the member rows' scopes
are merged (a VPN pool split into pieces reads as one range again) and their
services united; the evidence keeps the member row count. Access Review itself
still lists one row per expanded rule row.

Rows sourced from an SSL-VPN tunnel pool raise only `vpn_direct_to_ot`
(critical; SR 1.13 primary, SR 5.2 / 5.1, 62443-2-4 SP.07 for vendor users;
rows 4.1 / 2.1) when they reach L2 or lower without a DMZ jump host - one per
VPN chain **and user group** (a chain whose policy names no group: one for "any
SSL-VPN user"); the tail of a longer VPN chain is folded in. The group's
category (IT / vendor / other) comes from the operator's classification
(docs/management-networks.md, "VPN user groups"), else it is guessed from the
name and the finding says so; vendor groups add SP.07.

### NAT along a path

The walk that joins one permitting policy per firewall translates between
firewalls: a policy's source NAT (FortiOS `nat enable` → the egress interface
address, an IP pool, central SNAT) replaces the source the next firewall
sees, and the next firewall's VIP replaces a destination inside its external
address (double NAT: a VIP pointing at another firewall's VIP). The row keeps
the original source and the final destination; `nat` lists the translations.
Paths the reachability engine reads as denied only because it intersected
untranslated scopes are re-walked. A composed row whose source is one host at
another known level is dropped (P-10).

A firewall's explicit upload boundary is widened by its labelled interfaces:
any interface the operator labelled at a level outside the boundary's two
makes it a multi-leg firewall, one enforcement point per labelled level pair
(P-01; previously only DMZ and tunnel legs did).

### Dead-end permits and chain prefixes

A destination inside the network of the last firewall's egress interface (or
FortiOS zone) is **delivered**, whatever its device level - not a dead end.


A row whose destination scope **lives beyond** the level the row reaches (a
single host with a known level, or a scope inside one labelled interface
network) does not deliver its traffic there:

- if a longer row continues it (the same policies first, then more) it is a
  **prefix** - the longer row is the finding, the prefix is not raised;
- if nothing continues it, the next boundary drops the traffic: a
  **`dead_end_permit`** finding (SR 7.7 / 5.2, checklist 3.8). Evidence names the
  firewall and rule that drop it (path trace), policy-name markers (TEMP,
  LEGACY, TKT, ...), and attempts seen in the capture. low; medium when the
  capture shows attempts. Legacy leftover, half-finished change or over-broad
  upstream rule - a person decides.

Neither prefixes nor dead ends are reported as chain bypasses: they reach no
host at the row's destination level.

### Declared hops (VPN / access gateway → jump host)

A step between two hosts of one segment (VPN concentrator, access proxy such
as Teleport, or any broker → the DMZ jump host) crosses no firewall, so
nothing joins the paths on either side. The operator declares it
(`GET/POST/DELETE /access-paths/hops`, "Declared hops" panel on the Access
Review page): `from_ip` (gateway, leg 1 ends here) → `to_ip` (jump host, leg 2
starts here), optional service (`tcp/22,tcp/3389`, default any) and note. Both
hosts must exist in the site and, when both have a Purdue level, share it.
Suggestions list labelled gateway → jump host pairs not yet declared (only pairs
whose hosts exist, so every suggestion can be declared). Each listed hop carries
`from_known` / `to_known` / `level_mismatch`: the hop keeps composing, but the
panel shows "Re-check" when a host vanished or the two drifted to different
levels. Addresses are compared in canonical form (`2001:DB8::1` = `2001:db8::1`);
role spelling is case- and `-`/`_`-insensitive.
Composed rows built this way carry `declared_hop` and a `hop` object, and the
report/finding path label reads `… → L3.5 <gateway> ⇒ <jump> (declared hop) → …`.

Roles: approved-host role `remote_access_gateway` (or `Host.role`) marks the
gateway; `jump_host` (approved role or `device_type`) marks the jump host. The
remote-access checks (real-time FAZ and session fallback) use both: external →
OT is critical, external → jump host without coming through the gateway is
high, external → gateway is the sanctioned entry point, and external → anything
else on remote ports is critical.

Each row also records **initiation direction** (which zone opens the
connection), per IEC 62443 conduit semantics: a less-trusted lower zone
initiating *into* a higher zone is called out distinctly from the reverse.

## Enumeration engine

`enumerate_access_paths(db, site_id, *, direction="all"|"down"|"up",
boundary_only=True)`:

- Iterate every firewall in the site and every `upstream_chain`; a multi-fw
  path (e.g. `L4 –[FW1]– L3.5 –[FW2]– L2`) is one row and is "permitted" only
  if every hop permits it.
- For each permitted `(src scope, dst scope, service)` pull the per-hop
  `matching_rule` already produced by the engine; emit one row:
  `{src: {level, zone, scope}, dst: {level, zone, scope}, service/port,
    direction, chain: [fw·vdom·policy-id·name per hop], flags[], traffic}`.
- Compose `conduit_through_dmz` by joining an up-leg into a dual-homed host
  (present at two levels, e.g. a DMZ historian) with a down-leg out of it.
- Respect the per-ingest row budget (`IACS_MAX_RULE_ROWS_PER_INGEST`); cap and
  set `truncated` rather than running unbounded on a permissive firewall.
- `boundary_only=True` (default) emits only cross-zone / cross-Purdue paths,
  not intra-zone permits, to keep the list reviewable.

## PCAP overlay

For each enumerated path, match captured `NetworkSession` rows (via
`canonical_flow` + level lookup) and the permitting policy's hit /
`last_matched`. Mark the row's `traffic` **seen** (last-seen, count) or
**not seen in the capture window**. Config enumeration = what is *possible*;
the overlay = what was *captured*; the approved-conduit baseline = what is
*sanctioned*. All three are shown side by side. The overlay is additive — the
whole screen works with zero PCAP.

A PCAP is a sample, not a full record, so the overlay never says a path is
"unused": it says `not_seen` and prints the capture window it was not seen in.
**"Unused rule" is reserved for the existing `unused_policy` finding**, which
is based on rule hits (`last_matched`) over a review period, not on a capture.

## Review screen with manual classification (new)

New console page **"Access Review"** (site selector, sequence-guarded loaders,
no `innerHTML`, keyboard-operable rows — same conventions as the other pages).

One row per enumerated path. Columns:

1. **Select** (checkbox) — chooses the line for the report.
2. **Dir** — ↓ downhill / ↑ uphill / ⟷ composed.
3. **Source** — level · zone · scope.
4. **Destination** — level · zone · scope.
5. **Service** — proto/port(s).
6. **Permitting policy** — fw · vdom · policy-id · name (multi-fw chains list each hop).
7. **Flags** — badges from the taxonomy above.
8. **Traffic** — seen (last-seen, count) / not seen in capture (window) / — (no capture); rule hits shown separately.
9. **Classification** — dropdown: `unclassified` · `permissive` · `it_ot_bypass` · `reviewed_ok` · `exception`.
10. **Report** — include-in-report toggle (defaults on for any flagged row).

Filters: direction, boundary-only, flagged-only, traffic status, classification, report-include, level-pair,
firewall, service. Bulk actions on the current selection: set classification,
toggle report-include. The selection and classification **persist** (see data
model), keyed by a stable `tag_key` so they survive config re-ingest.

"Generate report" renders exactly the report-included rows with their
classifications.

### Roll-up of rows that differ only in one host (2026-10-11)

A policy whose destination is an address group of N hosts expands to N rule
rows, so one logical conduit (VPN user → jump host → every controller over
SSH) is N near-identical rows - 3,155 on the first production config. The
enumeration keeps every row (the per-host traffic overlay, tags and findings
depend on them); the screen and the report print one **line** per group.

* `app/parsers/access_path_groups.py` gives every path row two keys, set by
  `_enumerate` and returned by `GET /access-paths`: `group_dst` = everything
  about the row except the destination address (direction, the source's
  level / zone / scope, the destination's level / zone, services, protocols,
  the policy chain, pivots, declared hop, flags, reach, NAT); `group_src` the
  same with the source address left out. Classification, report flag,
  traffic and notes are not in a key. `roll_up(rows)` groups by `group_dst`,
  tries the rows left alone by `group_src`, and keeps the rest single.
* **Screen**: filter *Roll up similar paths* (on by default, remembered per
  browser). The visible rows (after the other filters, in the sort order) are
  rolled; a group is one `tr.ar-group` line - "N destinations · L2 · zone"
  (or "N sources") with the first four addresses, the shared cells, one
  traffic badge per status with its count (`Seen in capture ×12`), a
  classification select (`mixed (k)` when the members differ) and a report
  checkbox (indeterminate when they differ). The checkbox selects every
  member for the bulk bar; the select and the report checkbox apply to every
  member (`POST /access-paths/classify`, batched); the expander lists the
  member rows, each with its own controls. The card head says "rolled into M
  lines (G groups)"; paging counts lines.
* **Report**: within each classification group, rows of one classification
  are rolled the same way; the line reads "<source> → <pivot> → N
  destinations in L2 vlan_20 + …" with up to 8 addresses listed under it
  (`+k more`), traffic summarised per status ("Seen in capture on 12 of 47
  (31 sessions)", "Of 47: seen on 12 (…), not seen on 35"), rule hits summed,
  distinct notes joined. The counts stay per path: the intro's "N lines",
  the summary table and `counts.report_include` are unchanged; the intro
  adds "(M printed)" and a group header "(9) · 3 lines" when rolled.

## Data model

Table `access_path_tag` (model `app.models.AccessPathTag`, revision
`f7a8b9c0d1e2`):

- `id`, `site_id` (FK sites, NOT NULL, indexed `ix_access_path_tag_site_id`)
- `tag_key` String(512) NOT NULL — the row's stable identity (below)
- `kind` — `path` | `composed` | `unexplained` (CHECK)
- `firewall_device_id` (nullable, **no FK**), `vdom`, `policy_id` — descriptive
  copies of the permitting policy taken when the tag was written (composed
  rows: the first leg's first hop; unexplained flows: null). Never used for
  matching.
- `classification` — `unclassified|permissive|it_ot_bypass|reviewed_ok|exception` (CHECK, NOT NULL)
- `report_include` — nullable bool; NULL = use the row's default
- `note` (Text), `classified_by` (String(128), free text until auth, A-01),
  `classified_at` (set when a classification is written), `updated_at`
- unique index `ux_access_path_tag_site_key (site_id, tag_key)`

### tag_key (stable across re-ingest; never a DB row id)

| Row | Format |
|---|---|
| path (and intra-zone `same`) | `p:{firewall_name}:{vdom or -}:{policy_id}:{sha1(src\|dst\|service\|direction)[:16]}` |
| composed conduit | `c:{sha1(leg-1 policy keys\|leg-2 policy keys\|pivot ip\|services)[:16]}` |
| unexplained flow | `u:{sha1(client ip\|server ip\|proto\|port)[:16]}` |

- `src` / `dst` = `L{level}/{zone}/{scope}`; `service` = the row's service
  strings joined with `,`; a policy key = `{firewall_name}:{vdom or -}:{policy_id}`
  (a leg's hops joined with `;`).
- A multi-firewall chain is keyed on its **first** hop; the later hops'
  policy keys are appended to the hashed text so two chains sharing a first
  hop never collide.
- The firewall **name** (not its id) is used, so a re-uploaded config and a
  firewall deleted and re-added under the same name keep their tags.
- Identical configs in two sites produce identical keys; tags are stored per
  site, so they never leak.
- A tag whose key matches no current row (policy removed, renamed firewall)
  is returned in `orphaned_tags`, never deleted automatically.

Migration is idempotent, fresh `alembic upgrade head` is drift-free, and the
offline `--sql` render works on PostgreSQL (`CREATE TABLE IF NOT EXISTS`).

## API (contract for the Access Review screen and the report)

### GET /access-paths

Query: `site` / `site_id` (required when several sites exist; 422 when they
disagree), `direction=all|down|up`, `boundary_only` (default true),
`flagged_only`, `traffic=seen|not_seen|no_capture|partial`,
`classification=<enum>`, `report_include=true|false` (effective value),
`include_unmatched` (default true).

Row (`paths[]`):

```
{tag_key, src: {level, zone, scope}, dst: {level, zone, scope},
 service: [str], protocol: [str], direction: down|up|composed|same,
 chain: [{rule_id, firewall_id, firewall_device_id, firewall_name, vdom,
          policy_id, policy_name, action}],
 flags: [str], initiation: {level, zone, initiates},
 traffic: {status: seen|not_seen|no_capture|partial, sessions, last_seen,
           rule_hits, rule_hits_since, last_matched,
           capture_window?: {first, last},      # on not_seen / partial
           by_leg?: [traffic, traffic]},        # composed only
 classification, note, classified_by, classified_at,
 report_include, report_include_default,
 reach: "reaches" | "prefix" | "dead_end",      # MP-07, see below
 flags_at_reached_level?: [...],                 # prefix / dead_end only
 pivot?: {ip, level}, legs?: [{src, dst, service, policy_ids}]}   # composed only
```

`reach` (MP-07): a cross-boundary row whose destination scope lives beyond
the level it reaches delivers nothing there - `prefix` when a longer row
(same policies first, then more) continues it, `dead_end` when nothing does
(the `dead_end_permit` finding names the blocking firewall). Such a row keeps
only the flags that do not judge it by level (`permit_any`,
`cleartext_protocol`, `mgmt_protocol`, `direction_unverified`, NAT flags); the level-judged ones
(`it_ot_bypass`, `dmz_bypass`, `ot_upward_skip`, `industrial_proto_out_of_zone`,
…) move to `flags_at_reached_level`, and the row is out of the report by
default. `counts.by_reach` counts rows per value. A row whose source scope
lives at another level than the row's source level (one known host, or a
network inside a labelled interface network of another level, MP-06) is not
produced at all: it is the tail of a longer chain.

`unmatched_observed[]`: `{tag_key, client: {ip, level}, server: {ip, level,
port}, transport, direction, sessions, last_seen, flags, classification, note,
classified_by, classified_at, report_include, report_include_default}`.

Envelope: `paths, truncated, capture_window: {first, last}, counts: {total,
by_direction, by_flag, by_traffic, by_classification, report_include,
report_include_by_kind: {path, composed, unexplained}, orphaned,
unmatched_total}` (`report_include` = every line the compliance report prints
for the site, from `access_paths.report_lines()`, whatever the filters; POST
/access-paths/classify returns the updated value as `counts`), `orphaned_tags: [{tag_key, kind,
firewall_device_id, vdom, policy_id, classification, report_include (stored,
may be null), note, classified_by, classified_at, updated_at}],
orphaned_incomplete, unmatched_observed, unmatched_total,
unmatched_sessions, unmatched_capped, unmatched_incomplete,
`unlabelled_firewalls: [{firewall_id, firewall, unlabelled_interfaces}]` (D-11:
firewalls whose rules were applied without level evidence), site_id, site`.

`report_include_default` = the row has at least one flag AND its
classification is not `reviewed_ok` / `exception` AND it is not a prefix /
dead-end row (`reach`). `report_include` is the stored true/false when set,
otherwise the default.

### POST /access-paths/classify

```
request:  {site? | site_id?, items: [{tag_key,
           classification?, report_include? (true|false|null = reset to default),
           note? (<= 2000 chars), classified_by? (<= 128 chars)}]}   # 1..500 items
response: {items: [rows / flows in the GET shape, request order],
           site_id, site, findings_sync: {...}}
```

- Every `tag_key` must be in the site's current enumeration (paths,
  composed rows, intra-zone rows, unexplained flows); one unknown key —
  including a key that exists only in another site — returns 422 and nothing
  is stored. Duplicate keys, unknown item fields and invalid values are 422.
- Upsert per `(site_id, tag_key)`; an omitted field is left unchanged.
- After commit the route calls
  `app.parsers.access_path_findings.sync_findings_for_tags(db, site_id, tag_keys)`
  (wave 1: documented no-op stub returning `{"implemented": false, ...}`; a
  failure there is logged and never undoes the committed tags).
- Write route: `get_write_db` session. No auth / CSRF yet (A-01 deferred).

## Reporting & findings

- New PDF section **"Permitted Communication Paths & Permissive Policies"**:
  the report-included rows grouped by direction and boundary, each with the
  permitting policy, service, flags, traffic (seen / not seen in the capture
  window, rule hits separately), classification, and 62443 SR references.
  `orphaned_tags` can be listed as classified paths no longer present in the
  configuration.
- A row classified `permissive` or `it_ot_bypass` also raises a finding
  (sharing the `rule_it_ot_bypass` lifecycle, or a new `rule_permissive`
  check), so manual and automatic flags flow through the dashboard together.
  `reviewed_ok`/`exception` annotate and suppress the auto finding with the
  operator's note as the justification.

## Phase 1 notes (as built)

- One row per permitting policy (per hop) x resolved service x direction; policy names and actions come from the stored FirewallRule, and a deny is never listed as a permitting hop.
- A shadowed policy that can never fire produces no row.
- Paths the engine only infers (no real firewall on the boundary, `inferred_adjacency`) are excluded, so every row crosses a real firewall.
- Row cap `IACS_MAX_ACCESS_PATH_ROWS` (default 20000, falls back to `IACS_MAX_RULE_ROWS_PER_INGEST`); over the cap the result sets `truncated`.
- The overlay field was null until phase 2.
- Composed `conduit_through_dmz` paths were deferred here and are built in phase 2.

## Phase 2 notes (as built)

- Built as `observed` = {status, sessions, last_seen, rule_hits, last_matched} with statuses `observed` / `unused` / `no_data`; renamed in phase 3+4 wave 1 (below) to `traffic` with `seen` / `not_seen` / `no_capture`. A path is never called not-seen when nothing was captured.
- Sessions are oriented with `canonical_flow`, and each distinct flow is attributed to exactly one row: the first-match permitting policy, so overlapping policies don't double-count. Rule hits from FAZ/syslog are reported separately; a multi-firewall path reports the lowest hit count across its hops.
- `unmatched_observed`: crossing flows that no permitted row explains (traffic the config says can't pass), with direction-aware flags, capped with a total. `unmatched_incomplete` is set when the row budget truncated the list.
- Composed `conduit_through_dmz` rows: two permitted rows are joined through one specific pivot address (never an `all`/any scope). The row is informational and never `it_ot_bypass`. Its status is seen only if both legs are, and `partial` if one is.
- Query params added: `include_unmatched` (default true) and a status filter (now `traffic=`).

## Phase 3+4 wave 1 notes (as built, 2026-10-05)

- Status rename (owner: "unused" overclaimed; a PCAP is a sample): row field `traffic`, statuses `seen` (was observed), `not_seen` (was unused), `no_capture` (was no_data), `partial` (composed, one leg seen). Envelope `capture_window: {first, last}` (earliest `first_seen` / latest `last_seen` of the site's sessions); not_seen / partial rows repeat it. Rule hits stay separate: `rule_hits`, `rule_hits_since` (earliest counted hit event; for a chain, the latest of the hops' first hits), `last_matched`. Filter `traffic=`, counts `by_traffic`.
- "Unused rule" remains reserved for the `unused_policy` finding (rule hits over time).
- `access_path_tag` storage, tag merge, `orphaned_tags`, filters `classification=` / `report_include=`, and POST /access-paths/classify: see "Data model" and "API".
- Intra-zone rows are always enumerated internally (hidden unless `boundary_only=false`) so their tags are never reported orphaned; they are computed after the composed rows so they cannot use up the visible row budget.
- `app/parsers/access_path_findings.py`: `sync_findings_for_tags(db, site_id, tag_keys) -> dict` stub, with the contract in its docstring, for the findings work.
- Wave 2 (separate engineers): the Access Review screen (ui/) and the report section + findings (generate_report.py, alert_engine.py, the sync implementation).

## Phases

1. Enumeration engine + `GET /access-paths` (both directions, flags, multi-fw) — config only.
2. PCAP overlay (seen / not seen in capture).
3. Review screen + `access_path_tag` model + classify/select API.
4. Report section + findings integration.

## Open decisions (defaults chosen; correct if needed)

- **Granularity**: rows are per (permitting policy × resolved service ×
  direction × chain), grouped/filterable by level-pair and by named zone, with
  drill-down to concrete host/address scope. (Default.)
- **Does a tag raise a finding**: yes — `permissive`/`it_ot_bypass` raise or
  confirm a tracked finding; `reviewed_ok`/`exception` suppress with a note.
  Report inclusion is a separate per-row toggle so the operator controls the
  printed set independently of the dashboard. (Default.)
- **v1 enumeration scope**: all cross-boundary paths, both directions
  (downhill-bypass and OT-egress headline, upward-skip and DMZ-conduit next),
  filtered to cross-boundary by default. (Confirmed by owner.)
