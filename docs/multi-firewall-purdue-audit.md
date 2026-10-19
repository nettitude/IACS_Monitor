# Audit 2026-10-08: mapping access control across multiple firewalls onto Purdue levels

**Question:** how effective is the application at taking the access-control rules of several firewalls and
turning them into a correct picture of what can reach what, per Purdue level — the reachability matrix,
the host-to-host path, the access-path rows, and the chain / bypass findings built on them?

**Method:** four independent reviewers (level graph and topology; per-hop algebra and rule direction; what
the operator sees — rows, chain findings, cross-firewall checks; how rules and interfaces get their
levels), each building small firewall scenarios and running them through the real code. Every finding
below was re-run by hand afterwards; all are **confirmed** unless marked *plausible*. No code was
changed. Probe scripts are kept in the session scratchpad (`rv_topo/`, `rv_algebra/`, `rv_chain/`,
`rv_resolver/`).

> **Update 2026-10-08 — MP-01 to MP-24 fixed, MP-25 partly.** Firewalls sharing a level pair are now alternatives (OR) unless
> declared in series (paired group, confirmed upstream chain, confirmed inside↔outside link); host
> queries and the traffic overlay select the box whose labelled interface networks hold the flow's
> addresses, and the carrier MAC selects between boxes. The API reports `arrangement` /
> `alternatives` per enforcement point and `placement` per hop; the UI shows `A | B [parallel]` vs
> `A + B [series]`. A multi-leg box that reappears on a later hop of a path is left out of that hop
> (`already_crossed`) instead of the whole path being dropped. Firewalls with rules but no
> enforcement point are listed as `unplaced_firewalls` (API, UI banners, report); any verdict over an
> inferred hop is `unknown` while such a firewall exists, inferred hops are printed in the path, and no
> edge is inferred into a level with neither hosts nor labels. `declare_paired` refuses members on
> different level pairs, unhealthy paired groups are reported as `paired_group_warnings`, and the
> asymmetric-permit check compares paired members with or without a confirmed link. The rule-level
> resolver keeps multi-word zone names whole, follows reachability's lookup order with separate
> name and label maps, and takes the upload boundary when a firewall has no labels (one severity
> step lower, flagged); a rule side naming an interface without a level is another leg on a
> multi-leg box, uncertain on a partly labelled boundary, and listed as not judged. Cells are
> enumerated IT → OT first and a truncated enumeration is an informational finding; a boundary level
> between labelled legs is no longer a phantom leg (`label_conflicts`); per-firewall "rules not
> judged" reach the API, the UI and the report. Network-scoped sources are placed by the interface
> network that holds them, prefix / dead-end rows are marked `reach` and left out of the report,
> specific denies are subtracted across hops, and dead ends are traced through a representative
> address. Severity follows the source and destination band, `peer_link` suggests the peer's own
> level, same-level crossings through one firewall are evaluated, host paths report every level
> path, parallel uplinks are never suggested as a series pair, composition runs to three legs with
> notes on what did not compose, chain evidence carries per-hop scope and the change point, and
> VPN-sourced policies are judged once. Status per item is tracked in
> docs/code-review-remediation.md. The verdict and findings below describe the code **as audited**,
> before those fixes; the leftovers of MP-25 are the only open items.

## Verdict in one paragraph

The mapping is **sound for a linear Purdue stack** — one firewall, one declared series pair or one VDOM
chain per level boundary, every routed interface labelled. Inside that envelope the pieces are right: rule direction from zones and subnets, "exactly
this leg" on multi-leg boxes, scope and service intersection across hops, deny-dominates AND / OR tables,
NAT carried hop to hop with the original source kept for the findings, a config-only dead-end check
that names the blocking firewall. **It is not yet effective for sites with firewalls that share a level
pair but not a wire** — one firewall per cell or area, two plants in one site, a direct 4↔3 firewall
beside a DMZ chain, a three-leg DMZ firewall beside a two-leg one. There the engine ANDs devices that
never both see a packet, so permitted flows come back "denied" (attributed to an uninvolved firewall's
implicit deny), access-path rows disappear, `chain_it_ot_bypass` findings are silently lost, and
captured traffic through the real firewall raises a false `session_no_permitting_rule`. The physical
placement information that would fix this is already in the database (interface subnets, confirmed
links, shared segments, paired groups, upstream chain, carrier MAC) but none of it selects enforcement
points. The second structural weakness is label dependence without safeguards: a firewall with no label
vanishes and the engine invents an unfirewalled hop in its place; a disagreement between the three label
sources is merged into phantom legs; and the rule-level checks still have their own, older, resolver
that differs from the reachability one in three ways already fixed on the reachability side.

## What works (confirmed)

| Area | Confirmed behaviour |
|---|---|
| Series chain | L4 -[A]- L3.5 -[B]- L3 -[C]- L2 with permits on all three: ONE row, 3-entry chain, `it_ot_bypass`, severity by destination; removing B's permit removes the row and `dead_end_permit` names FW-B as the blocker with no capture needed |
| Scope intersection | Two series firewalls with different partial scopes: cell scope = intersection (`10.10.5.0/24 → 10.20.1.5/32`, tcp/443); host 10.10.9.9 (outside FW2's scope) correctly denied |
| AND / OR tables | Deny > unknown > no_policy > partial/permitted in series; order-independent; FW1 unresolved object + FW2 deny = denied, + FW2 permit = unknown |
| Multi-leg boxes | 4→3 on a 4/3.5/3 firewall uses the 4↔3 crossing only; `port1 → port3` does not permit 4→3.5; `any → any` permits all three crossings |
| NAT | Hide NAT, VIP on the outer or inner firewall, double VIP: one end-to-end row with the ORIGINAL source level; `nat_hides_source_into_ot` lists the original sources |
| Carrier filter (LS-03) | Routing switch beside a firewall: carrier MAC selects the device; no carrier = OR (conservative) |
| Labels | Zone text beats CIDR in both resolvers; a zone with members on two levels resolves to {3, 2} and is flagged as a bypass from L3; suggestions are typed, sourced and never auto-promoted; `svi_auto` / `ssl_vpn_auto` follow label changes; site isolation of the resolver holds |

## Findings

Severity is by impact on what an operator concludes about a real multi-firewall site.

### High

| ID | Finding | Where | Evidence |
|---|---|---|---|
| MP-01 *(fixed 2026-10-08)* | **Parallel firewalls on one level pair are AND-ed.** Every distinct box on boundary (lo, hi) is a factor of one series product; nothing (paired group, confirmed link, shared segment, `upstream_firewall_id`, interface subnets, carrier MAC between two firewalls) selects which box a flow traverses. Two cell firewalls FW-A (L3 / L2 cell 1) and FW-B (L3 / L2 cell 2), each permitting SCADA → its own PLCs: SCADA → PLC-cell-1 = **denied** ("FW-A permit, FW-B implicit_deny"), cell 3→2 = denied, access-path rows = 0; with FW-A `any → any` the open cell firewall is invisible; a captured SCADA → PLC-1 flow becomes `unmatched_observed` + `session_no_permitting_rule`; when both permit, a flow is attributed "seen" to a row whose chain includes the firewall it never crossed (that "seen" steps the chain severity up). Adding an unrelated cell firewall to a site removes an existing `chain_it_ot_bypass` finding (0 rows, 0 findings). The better-segmented the site, the more wrong the answer. The API doc says "denied = all paths are blocked by at least one deny rule" and the matrix UI lists "2↔3 FW-A, FW-B" with no series/parallel hint. | `reachability.py` `_hop_eps`, `hop_alternatives` (~1897-1940), docstring line 96; `access_paths.py` `_stage_sets` (211-224); `routes.py` ~3058 | `rv_topo/p1_cells.py`, `p1b_missed_bypass.py`, `p2_p3.py`; `rv_algebra/probe_a5.py`; `rv_chain/probe_c5.py` |
| MP-02 *(fixed 2026-10-08)* | **Path pruning drops a whole path when a multi-leg box reappears.** `_uses_box_twice` rejects a path if ANY box of a later boundary was already seen, instead of removing that box's EP from the later hop. A 3-leg FW-C (4 / 3.5 / 3, permits 4→3.5 only) beside a 2-box chain FW-A (4/3.5, any) → FW-B (3.5/3, any): 3.5→3 = denied (FW-B permit AND FW-C deny), 4→3 = denied (FW-C alone; the A→B route is pruned), one access-path row 4→3.5 with the chain `[FW-A, FW-C]` that does not exist. | `reachability.py` `_path_between_levels._uses_box_twice` (~2702-2711) | `rv_algebra/probe_a3b.py` |
| MP-03 *(fixed 2026-10-08)* | **An unlabelled firewall vanishes and an unfirewalled hop is invented in its place.** A firewall with no interface level and no upload boundary builds no enforcement point; `_infer_flat_edges` then joins the two levels it separated with a "nearest" flat edge; a flow the missing firewall explicitly denies is reported **permitted** (path string `4 → [3↔4] → 2`, the inferred hop hidden; `inferred_adjacency` is in the JSON but rendered nowhere); chain findings are blind beyond that level; `unlabelled_firewalls` is empty (it lists only firewalls that produced a `direction_unverified` row); the report warns only when the whole site has zero levels. "Nearest" edges are also inferred into levels with no hosts and no firewall (0-1, 1-2, 4-5), yielding baseless cells such as 4→0 partial. `_flat_downgrade` turns only *denied* into *unknown*, never *permitted*. | `reachability.py` `_add` (844-872), `_infer_flat_edges` (2574-2639), `_flat_downgrade` (2714-2722); `access_paths.py` `_unlabelled_firewalls` (869-886); `generate_report.py` ~852 | `rv_topo/p4_p5.py`; `rv_resolver/probe4.py` |
| MP-04 *(fixed 2026-10-08)* | **A declared paired (series) group is never consulted.** Reachability reads only `ha_secondary_ids`; series semantics arise solely from two boxes carrying the same level pair. (a) Members whose transit link is labelled differently (FW-OUT port2 = 3, FW-IN port1 = 3.5 "DMZ") land on different boundaries: the denying inner member drops off the 4→3 path (permitted), and the stray 3.5 makes `_site_has_dmz()` true so every 4↔3 row is flagged `dmz_bypass` on a site with no DMZ. (b) `cross_fw_asymmetric_permit` compares only confirmed links and segments, so a paired group without a confirmed link is not compared at all: a one-sided permit on one member is invisible everywhere (no row because the pair is AND-ed, no asymmetric finding, no dead end), with no warning that the pair is unlinked. `docs/firewall-groups.md` promises the asymmetric check "compares exactly these". | `firewall_groups.py` `declare_paired` (214-248), `confirmed_pair` (515-522); `reachability.py` 734-741; `cross_fw_findings.py` 710-749 | `rv_topo/p6_p8.py`; `rv_chain/probe_groups.py` |
| MP-05 *(fixed 2026-10-08)* | **The rule-level checks still split zone names on whitespace.** Fix C-05 (multi-word interface / zone names) was applied to `fortios_zones.zone_tokens`, `rule_shadow` and `reachability`, but `_RuleZoneResolver.resolve_checked` still uses `_split_zone_value` (`[,\s]+`), so a policy `port1 (L4) → "OT Zone" (L1)` resolves to `(set(), False)`, is marked unevaluated and raises no `rule_it_ot_bypass` — while the access-path row for the same policy is flagged `it_ot_bypass`. Affects every rule twin (`rule_it_ot_bypass`, `rule_mgmt_wrong_zone`, `rule_ot_it_dependency`, `rule_insecure_protocol`, `rule_cleartext_creds`, `rule_conduit_drift`, `review_disabled_rules`). The same class already uses `zone_tokens` for `names_link`. | `alert_engine.py` `_split_zone_value` (~4892), `resolve_checked` (~5061) | `rv_resolver/probe1.py` (`C05-space-zone`) |

### Medium

| ID | Finding | Where | Evidence |
|---|---|---|---|
| MP-06 *(fixed 2026-10-08)* | **Network-scoped sources at another level produce impossible rows and multiply findings.** `_src_elsewhere` (P-10) and `_foreign_source` recognise only a single host with a known level; `_scope_level` (interface CIDR → level) is used for destinations only. 4-firewall chain, every policy `10.4.0.0/24 → plc`: with a /32 source 4 rows and 1 finding; with the /24 source 10 rows and **three** `chain_it_ot_bypass` high findings ("L4 10.4.0.0/24 → L1", "L3.5 10.4.0.0/24 → L1", "L3 10.4.0.0/24 → L1") plus a row "L2 10.4.0.0/24 → L1" — the /24 is the network behind FW-A's L4 port; no L3 / L3.5 / L2 host carries it. On an 8-firewall chain with /16 scopes one real path yields up to 7 findings with wrong source levels. | `access_paths.py` `_src_elsewhere` (854-866); `chain_findings.py` `_foreign_source` (201-221), `_scope_level` (246-272) | `rv_chain/probe_c4src.py`, `probe_c6b.py` |
| MP-07 *(fixed 2026-10-08)* | **Prefix / dead-end rows are shown and reported as real paths with flags computed against the wrong level.** One IT → L2 path appears as three rows (L4→L2 `it_ot_bypass`, L4→L3 "10.2.0.20/32" `dmz_bypass`, L4→L3.5), all `report_include=True`, all counted in `by_flag` and printed in the PDF; `classify_reach` knows they are `prefix` but that never reaches the row, so the review screen says "L3 destination" for an L2 host and shows `dmz_bypass` where the findings engine (correctly) raises none. 30 real paths → 120 rows, 30 flagged `dmz_bypass` without a finding. | `access_paths.py` 729-795; `chain_findings.py` `classify_reach` (340-367) | `rv_chain/probe_c1_prefix.py`, `probe_c6.py` |
| MP-08 *(fixed 2026-10-08)* | **Truncation removes the IT → OT rows first and the findings run does not say so.** The matrix is built in `permutations(sorted(levels))` order (src 0, 1, 2, 3, 3.5 before 4 / 5); with `IACS_MAX_ACCESS_PATH_ROWS` = 45 on a site with 40 upward L1→L2 permits, every L4→L1 row is gone, `chain_it_ot_bypass` / `chain_mgmt_wrong_zone` go from 30 to **0**, and the review result and `last_review_info` carry no truncation marker (`chain_findings` calls `_mark_incomplete` but not `_record_truncation`). Only the Access Review chip and one italic PDF line mention it. | `reachability.py` ~2795; `access_paths.py` 796-802; `chain_findings.py` 372-373 | `rv_chain/probe_c6b.py` with `IACS_MAX_ACCESS_PATH_ROWS=45` |
| MP-09 *(fixed 2026-10-08)* | **A known-but-unlabelled interface or zone member in a rule side means "any leg", unflagged.** `_zone_levels` returns `None` for a token that matches no *levelled* interface even when the interface exists on the firewall (wan1, SD-WAN member, tunnel, loopback, mgmt; PAN-OS zones with unlabelled members — the mixed-vendor `untrust`). `compatible()` then accepts every leg; because the other side resolved, `direction_unverified` stays False. A `wan1 → port2 (L3)` permit becomes a 4→3 "permitted any" row with `permit_any` / `insecure_protocol` / `industrial_proto_out_of_zone` and no warning; on a 3-leg box one unresolved side fans the rule out over every crossing of the other side. | `reachability.py` `_zone_levels` (~1262-1321), `rule_applies` (~1431), `direction_unverified` (~1403-1413) | `rv_algebra/probe_a4.py` (row 3), `probe_a3.py` |
| MP-10 *(fixed 2026-10-08)* | **Specific denies in front of a permit-any are not subtracted across hops.** A device whose terminal rule is permit-any returns `permitted` with `denied_services` as a string list only; `_combine_verdicts` skips permitted verdicts and `_union_verdicts`' partial branch drops the list. FW-A permits 443,502; FW-B denies 502 then permits any: cell 4→2 = `partial ['tcp/443,502'] denied []`, access-path row lists tcp/502 and raises `it_ot_bypass` for a Modbus port FW-B explicitly blocks; the host path for tcp/502 says denied (inconsistent with the cell). | `reachability.py` ~1824, `_combine_verdicts` 369-370, `_union_verdicts` 392-401; `access_paths.py` `_ep_candidates` 259-312 | `rv_algebra/probe_a8.py`, `probe_a8b.py` |
| MP-11 *(fixed 2026-10-08)* | **Severity ignores the source level, and L3 is "IT side" for the bypass but "OT" for egress / NAT.** `chain_it_ot_bypass` severity = destination band only: L5→L0, L4→L1, L3.5→L1 and L3→L1 are all high (critical when seen); L4/L5→L2 medium; L3→L2, L3.5→L2 nothing; L4/L5→L3 nothing at all when the site has no DMZ. An internet → PLC chain ranks equal to a SCADA server → PLC chain, below `vpn_direct_to_ot` and `session_it_ot_bypass` (critical), and an L3 source is explained as "a compromised IT host — the most exposed part of the network". `path_ot_internet_egress` and the NAT checks treat L3 as OT. | `purdue.py` `is_it_side` (272-275); `chain_findings.py` 539-541; `explain.py` 42-49; `access_paths.py` 390-394 | `rv_chain/probe_c2.py` (full pair table) |
| MP-12 *(fixed 2026-10-08)* | **Device boundary vs interface labels: a disagreement is merged into phantom legs, nothing surfaces it, and the topology page disagrees with the engine.** Device 4→3 with interfaces 4 / 2 → EP legs [2, 3, 4]: cell 3→2 "denied" and a host query to L3 "denied [implicit_deny]" although no L3 leg exists (should be no_policy); `firewall_level_boundaries` (topology page) gives {(2,4), (3,4)}. Device 4→3.5 with interfaces 4 / 3 → a phantom DMZ leg that enables site-wide `dmz_bypass` flagging. No code compares `FirewallDevice.purdue_zone_*`, `Firewall.purdue_level_ingress/egress` and `FirewallInterface.purdue_level`. | `reachability.py` `_add` (`legs = set(legs) \| {zf, zt}`); `topology_manager.py` `firewall_level_boundaries` (1029-1053) | `rv_topo/p6_p8.py` (P8, P8b) |
| MP-13 *(fixed 2026-10-08)* | **The `peer_link` level suggestion assumes a series pair and is wrong for a chain.** A confirmed link (same subnet) suggests the peer's level ±1 by side. Right for the paired convention (transit /30 labelled 3 on FW-OUT, 4 on FW-IN); wrong when the downstream firewall guards the NEXT boundary: INNER's uplink on the L3 segment is suggested **L4**; accepting it yields EP boundaries {(3,4) OUTER, (2,4) INNER} — the real 3↔2 boundary is gone — a false `it_ot_bypass` row and a false `rule_it_ot_bypass` finding, and one subnet labelled at two levels. | `topology_manager.py` `run_purdue_suggestions` peer_link (732-759) | `rv_resolver/probe5.py` |
| MP-14 *(fixed 2026-10-08)* | **Alias-vs-zone precedence and name-map collisions differ between the two resolvers** (fix C-09 applied to reachability only). The twin resolver takes an interface ALIAS over a FortiOS zone of the same name (`port2` alias "OT" at L3 vs zone OT = {port3 L1}: twins {3}, reachability {1} → an L4 → L1 permit gets no `rule_it_ot_bypass`), and its one flat name map lets another interface's `zone_label` / alias overwrite a real interface name in DB order (`dmz` L3.5 vs `port9` zone_label "DMZ" L3: twins {3}, reachability {3.5}). | `alert_engine.py` ~4942-4946, ~5072; `reachability.py` ~1286 | `rv_resolver/probe3.py` |
| MP-15 *(fixed 2026-10-08)* | **The upload boundary (`purdue_zone_from/to`) never reaches the rule twins.** A 4/2 firewall with no interface labels: reachability builds EP (2,4) with every rule "both ways" and `direction_unverified`; chain reviews skip unverified rows ("left to the rule twins"); the twins see `(set(), False)` → **zero findings anywhere** for a permit-all 4→2 policy. The docs do not say the parameter does not drive the rule checks. | `alert_engine.py` `_RuleZoneResolver` (no reference to the boundary); `chain_findings.py` 26-31 | `rv_resolver/probe2.py` |
| MP-16 *(fixed 2026-10-08)* | **A same-level crossing through one firewall is "same level, no boundary traversal" even when explicitly denied.** Two L3 legs of one firewall (10.3.1.0/24, 10.3.2.0/24) with a deny between them: `compute_path` returns `intra_level` before consulting any firewall; only `enumerate_access_paths(boundary_only=False)` lists the permits, the deny is invisible everywhere. | `reachability.py` ~2977-2982; `routes.py` ~3138; `ui/index.html` ~3792 | `rv_topo/p4_p5.py` (P4) |
| MP-17 *(fixed 2026-10-08)* | **Host queries return the most permissive level path and present it as *the* path.** FW-X 4↔3 direct (permits any) beside FW-Y1/Y2 4↔3.5↔3 (https only): `it → ops tcp/22` = permitted via [3↔4], the DMZ chain never shown; with FW-X deny-all, permitted via the DMZ chain. Right as an upper bound for findings (both rows are emitted), misleading as a determination; the engine never checks which firewall the host actually sits behind. | `reachability.py` `_compute_path_inner` 2994-3008 | `rv_topo/p2_p3.py` (P3) |
| MP-18 *(fixed 2026-10-08)* | **Link detection and the paired suggestion classify two parallel cell firewalls as "in series on one boundary".** Two uplinks on the same upstream subnet are "high … definitely connected" and `suggest_paired` ("linked firewalls that all enforce L3 / L2: in series on one boundary") steers the operator to declare the series pair the engine already assumes — evidence of parallel placement read as series. | `topology_manager.py` `_overlap_confidence` (113-136); `firewall_groups.py` `suggest_paired` (289-323) | `rv_topo/p6_p8.py` (P6b) |
| MP-19 *(fixed 2026-10-08)* | **`dead_end_permit` cannot name the blocking firewall beyond /32 scopes.** `_blocking_point` traces `compute_path` only when both scopes are single hosts; for `10.4.0.0/24 → host` the text is "Which firewall drops it is not known"; for `dst = all` no dead end is detected and the row reads as a legitimate "L4 → L3.5 any" permit. | `chain_findings.py` `_blocking_point` (681-718) | `rv_chain/probe_c3.py` |

### Low

| ID | Finding | Where |
|---|---|---|
| MP-20 *(fixed 2026-10-08)* | Confirmed links, shared segments, `upstream_firewall_id` and `topology_confirmed` have no effect on reachability, access paths or chain findings (readers: `cross_fw_*` pairing, paired *suggestion*, `peer_link` *suggestion*, UI chain). The operator procedure has them confirmed; nothing says they do not shape the path model — only interface labels do. | `topology_manager.py` 301-516; grep: zero references in `reachability.py` / `access_paths.py` |
| MP-21 *(fixed 2026-10-08)* | Composition is two legs through a single-address pivot or a declared hop; composed rows are never legs (vendor → gateway → L3 server → PLC never joins end to end), and a /24 pivot on both legs composes nothing with no note why. | `access_paths.py` `_compose_conduits` (1053-1168) |
| MP-22 *(fixed 2026-10-08)* | Chain-finding evidence lists hops (firewall + policy id) but drops each policy's src / dst / service, so nothing marks the `any → any` hop or the narrowest policy; `dead_end_permit.device_name` is the last permitting firewall, not the blocker. With 8 firewalls the operator opens every policy to find the change point. | `access_paths.py` `_chain_entry` (325-335); `explain.py` 47-49, 565-575 |
| MP-23 *(fixed 2026-10-08)* | A VPN-sourced policy is reported three times (`vpn_direct_to_ot` critical + `rule_it_ot_bypass` medium + `rule_mgmt_wrong_zone` medium); `vpn.py` says generic findings skip VPN rows but only the chain reviews do; the IPsec dial-up finding text says "SSL-VPN user". | `alert_engine.py` `_TwinRunContext.permit_rows`; `vpn.py` line 28 |
| MP-24 *(fixed 2026-10-08)* | Per-firewall "rules not judged" counts (`sides_unresolved`, unevaluated rules, A-09) reach only the log — never the API, Findings page or report coverage. | `alert_engine.py` ~7246 |
| MP-25 *(partly fixed 2026-10-08)* | Smaller items: `_union_verdicts([partial, unknown]) = partial` (the service list presented as definitive); an SNAT pool address inside the downstream firewall's far-side subnet with `srcintf any` is placed on the wrong leg (*plausible*); with no carrier an ACL-less routing switch beside a firewall makes the cell "permitted any" and hides the firewall's policy from the matrix (per LS-02 design, no `via` marker); HA-secondary labels are loaded but unused (labelling only the secondary yields a cluster with no EP and no notice; *plausible*); one mislabelled host is "subnet" flat-edge evidence that `_flat_downgrade` treats as certain (*plausible*); `carrier_fw_id` never chooses between two firewalls; `subnet_level` is order-dependent for a transit subnet labelled at two levels (*plausible*); a tunnel that stops being remote access keeps its auto L5 (`ssl_vpn_auto`); 30 host-pair permits on 4 firewalls = 60 chain findings with no per-firewall-set roll-up. | `reachability.py` 392-401, 1087-1102, 1903-1911, 2619-2623; `forti_config_parser.py` `_vpn_tunnel_level`; `chain_findings.py` 461-513 |

## Effectiveness assessment

**Completeness.** For a linear stack the row list and the chain findings are complete and the dead-end
check closes the "outer permits, inner blocks" gap without a capture. Completeness fails hard in two
situations: parallel firewalls on one level pair (MP-01, MP-02, MP-04b — rows and findings vanish,
captured traffic is misjudged) and truncation (MP-08 — the IT → OT findings are the first to go, with no
signal in the findings).

**Correctness of the level mapping.** Correct whenever every interface is labelled, the labels agree
with the device boundary, and the scopes are single hosts. It degrades without warning for
network-scoped sources (MP-06 — impossible source levels, findings multiplied), for an unlabelled
firewall (MP-03 — a permit is invented), for a known-but-unlabelled interface in a rule (MP-09 — a
permit is invented and not flagged), and for conflicting label sources (MP-12). The two resolvers (rule
twins vs reachability) have drifted apart (MP-05, MP-14, MP-15); three divergences are fixes applied on
one side only.

**Purdue semantics.** L3.5 is handled consistently. L3 is not: IT side for the bypass checks, OT for
egress and NAT (MP-11), and the bypass severity looks only at the destination band, so "internet → PLC"
and "SCADA → PLC" score the same and share one explanation.

**Actionability.** Chain findings list the hops but do not characterise them (MP-22); the dead-end check
goes mute beyond /32 scopes (MP-19); the "most permissive path" is presented as the path (MP-17); the
operator is never told which firewalls were not placed or which rules were not judged (MP-03, MP-24).

**What the operator must do today to keep results correct.** Label every routed interface of every
firewall (HA primaries too) and check the "Enforcement points" line lists every firewall; never rely on
the upload boundary alone; label series pairs identically (port1 = up level, port2 = down level); do not
put two *independent* firewalls that share a level pair in one site — the only faithful workaround today
is one site per independently firewalled cell or plant, giving up cross-cell analysis; treat
`inferred_adjacency` in the JSON as "no firewall was found here"; and use `boundary_only=false` to see
same-level crossings.

## Recommended fix order

1. **Placement-aware enforcement-point selection (MP-01, MP-02, MP-04, MP-18, MP-20).** Make "in
   series" an explicit relation: a confirmed paired group, a DOWN-leg → UP-leg confirmed link, or a VDOM
   chain. Distinct boxes on one level pair are **alternatives (OR)** unless declared series; for host
   queries keep only boxes whose labelled interface subnets contain the source or destination (the
   `_Carriers` logic in `topology_diff.py` already does this for the per-device fallback), and let
   `carrier_fw_id` choose between firewalls. Make path enumeration box-aware (remove the reused box's EP
   from the later hop instead of dropping the path). Validate at `declare_paired` that the members share
   a level pair; compare paired members in `cross_fw_*` whether or not a link is confirmed; label a
   same-level link "shared segment (parallel)", never series. Add the missing test shape: two
   independent cell firewalls, and a 3-leg DMZ firewall beside a 2-leg chain.
2. **Surface what is not modelled (MP-03, MP-08, MP-24, MP-12).** List every firewall with rules but no
   enforcement point (`unplaced_firewalls`) in reachability / access-path output, the UI banner and the
   report coverage; print inferred hops in the path string and never report a *permitted* host result
   that rests on an inferred hop as better than *unknown*; do not infer "nearest" edges into levels with
   neither hosts nor labels; enumerate downhill cells first and record truncation on the chain reviews
   (informational finding); emit a `label_conflict` warning when device boundary and interface labels
   disagree and make `firewall_level_boundaries` use the engine's EP builder; return per-firewall
   "rules not judged" counts.
3. **One side resolver (MP-05, MP-09, MP-14, MP-15).** Route `_RuleZoneResolver` through
   `fortios_zones.zone_tokens` and the reachability lookup order (zone def → exact name → alias /
   zone_label → legacy zone), with exact-name and label maps kept separate; treat a token that names a
   known-but-unlabelled interface as "not this leg" on a multi-leg box (and uncertain on an explicit
   boundary); feed the upload boundary into the twins (outside → hi, inside → lo, `level_source =
   "boundary"`, one severity step lower). Add parity tests: every reachability side-resolution test
   runs against the twin resolver too.
4. **Rows and findings (MP-06, MP-07, MP-10, MP-19).** Resolve a source scope's level from the labelled
   interface network containing the whole scope and skip or mark rows whose source lives at another
   level; mark prefix / dead-end rows (`reach: prefix|dead_end`, excluded from `by_flag` and
   `report_include` by default); carry denies as pieces and subtract them in `_combine_verdicts`
   (including for "permitted" hops) and keep `denied_services` through `_union_verdicts`; trace the dead
   end with a representative address of a network scope.
5. **Purdue semantics and explanations (MP-11, MP-13, MP-16, MP-17, MP-21, MP-22, MP-23).** A
   (source band, destination band) severity table with source-aware `why` text; `peer_link` suggests the
   peer's own level unless the pair is declared series; evaluate same-level crossings through one
   firewall's legs (or word `intra_level` as "not evaluated"); return `paths_evaluated` and say "most
   permissive of N"; keep per-hop src / dst / service in chain entries and name the recommended change
   point; iterate composition to a small depth; drop VPN-sourced rows from the generic twins.

Items 1-3 are what make multi-firewall verdicts trustworthy in both directions (no false denies, no
invented permits); 4 and 5 make the findings count and read correctly.
