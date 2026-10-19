# HA clusters and paired firewalls

Two relationships between firewalls that look alike on a diagram and behave in
opposite ways. Both are **declared by the operator**; the app suggests them but
never changes the analysis until a group is confirmed.

| | HA cluster (`kind = ha`) | Paired firewall (`kind = paired`) |
|---|---|---|
| What it is | Two or more configs of **one** logical firewall (active/passive or active/active) | Two or more firewalls enforcing **one boundary in series**, usually two vendors (NIST SP 800-82 "paired firewall" DMZ) |
| Traffic passes | **one** member | **all** members |
| Analysis | The **primary** member's rules are the cluster's single enforcement point (reachability, access paths, chain counts). Other members are compared with it. | Each member is its own enforcement point (a crossing must be permitted by every one). |
| Differences between members mean | config-sync **drift** → `ha_config_drift` (SR 7.6 / 7.2, checklist 7.4; high when a permit differs) | a real **asymmetry** → `cross_fw_asymmetric_permit` |
| Findings | A member's duplicate findings are folded into the primary's (config findings closed with a note; rule findings not raised during review runs) | normal |
| 62443 manual check | — | `paired_firewall_vendor_diversity` (SR 5.1 / 5.2, checklist 1.3): open until an operator attests, for checklist id `PF-<group id>`, that the members are different vendors. Acknowledge the finding to accept a single-vendor pair as a documented risk. The vendors recorded from the uploaded configs are shown as information only. |

An HA cluster can be one member of a paired firewall (it counts as one unit).

## How to declare

- **HA:** upload the second member's config with `?ha_peer=<first member's firewall name>`
  (`POST /ingest/fortigate-config`), or `POST /topology/ha-pairs {firewall_ids, primary_id?, name?}`.
  Suggested when two uploaded configs carry the same `config system ha` group name / id and an HA mode.
  Link and shared-segment proposals never pair a cluster's members (they share subnets).
- **Paired:** `POST /topology/paired-firewalls {firewall_ids, name?}`. Suggested for firewalls (or
  clusters) that touch the same set of interface Purdue levels and are linked to each other.
- **List / dissolve:** `GET /topology/firewall-groups` (groups + suggestions),
  `DELETE /topology/firewall-groups/{id}`. `GET /topology/state` also carries `firewall_groups` and
  `group_suggestions`.
- **Console:** Firewall Topology page — "Link & group proposals" lists the suggestions with Confirm,
  the confirmed groups with Dissolve, and each firewall column shows its HA / paired badge.
  Attestation page — one row per paired firewall (`PF-<id>`) when a site is selected.

## How the asymmetric-permit check uses them

A confirmed paired group decides: two linked firewalls are compared only when they are in the same
paired group. Firewalls in no group fall back to the interface-level heuristic (same set of levels
= serial pair). HA members are never compared with each other (drift covers them) and a non-primary
member is not compared with its neighbours.

Members of a paired group are compared **whether or not a link is confirmed** (MP-04): with no
confirmed link or shared segment the check uses the two interfaces that share an IP network (the
transit), and failing that the members' whole rulesets (the finding's `iface_a` then reads
"FW-X (paired group, link not confirmed)"). `run_cross_fw_checks` reports such pairs as
`paired_unlinked`.

## Validation and health

`declare_paired` refuses members that are already placed on **different level pairs** (422: "paired
firewalls must enforce the same level pair: FW-OUT L3↔L4, FW-IN L3↔L3.5 …"). The convention is that
each member labels the transit link as the *far* side — the outer member's transit leg carries the
inner level, the inner member's transit leg the outer level — so both land on one boundary. Members
with fewer than two labelled levels are not judged (not placed yet).

Afterwards `paired_group_warnings` (returned by `GET /reachability`, `/reachability/path` and
`/access-paths`, shown as a banner on the Reachability and Access Review pages) names groups whose
members sit on different level pairs (`level_mismatch` — they are evaluated on different boundaries,
not in series), have a member with fewer than two levels (`unplaced_member`), or have no confirmed
link / shared segment between them (`unlinked`).

## Model

`firewall_groups (id, site_id, kind, name, primary_firewall_id, note, created_by, created_at)`,
`firewalls.ha_group_id / paired_group_id` (FK, ON DELETE SET NULL), `firewalls.ha_mode /
ha_cfg_group` (from `config system ha`, suggestions only). Migration `c1d2e3f4a5b6`.
`primary_firewall_id` is a plain id (a reverse FK would make the two tables mutually dependent); a
stale id falls back to the lowest member.
