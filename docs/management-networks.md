# Declared management and engineering networks

IEC 62443-3-3 SR 1.3, SR 2.1 and SR 5.1 RE1 (workbook rows 2.5, 5.1, 5.5, 8.4, 9.5) require privileged access to OT equipment to come only from dedicated zones. Which networks form those zones is an operator decision. Before this work the application guessed: from the baseline's approved hosts (exact IPs only), from Purdue levels, and from the words "mgmt / management / admin" in interface names. Now the operator records it, per site, and every affected check reads the same record.

## Management vs engineering

Two kinds of privileged access, with different risks:

| | Management | Engineering |
|---|---|---|
| Who | Admin workstation, jump host | Engineering workstation (EWS) |
| Target | Infrastructure: firewalls, switches, servers, the OS of HMIs / historians | Controllers and field devices at L0-L2: PLCs, RTUs, drives, safety systems |
| Typical protocols | SSH, HTTPS, SNMP, RDP | Vendor programming / industrial writes: S7comm, EtherNet/IP-CIP, Modbus writes, DNP3 control; the device's web / SSH UI |
| What can go wrong | Network / security configuration changes | Process logic changes, program downloads, forces |
| Typical location | Management / OOB network | Engineering zone at L3 (site operations) or L2 (area control) |

Every declaration carries a **purpose**, management or engineering:

- An **engineering** source is approved toward OT equipment (destination L0-L2) and for industrial write / program operations. It is never approved for infrastructure admin: firewall admin access, admin trusted hosts, or management of IT-side servers.
- A **management** source is approved for management access anywhere. It is not an engineering source for industrial writes.

## What can be declared

| Kind | Meaning | Example |
|---|---|---|
| Network (`subnet`) | Every address in the CIDR is a source of its purpose. Narrowest allowed: /8 (IPv4), /32 (IPv6). | `10.10.8.0/24` management "IT admin LAN"; `10.20.2.0/24` engineering |
| Trusted host (`host`) | One `admin_ws` or `jump_host` (management) or `engineering_ws` (engineering). /28 or narrower. The purpose follows the role. Kept apart from the audit baseline, so no baseline is needed. | `10.20.2.30` engineering_ws |
| VLAN (`vlan`) | A site-wide VLAN id. Its subnets are the networks of firewall VLAN interfaces with that id; hosts the switches place on it (MAC table) are sources too. | VLAN 20 engineering |
| Zone / interface (`name`) | Reclassifies a firewall interface, FortiOS zone or alias name, on one firewall or every firewall of the site. It becomes a management zone, an engineering zone, or **neither** (whatever its name says). Its subnet becomes a network of that purpose. Re-declaring a name updates it. | `OOB-NET` on FG-1 = management; `EWS-LAN` = engineering; `mgmt-ot` = neither |

A network or VLAN can also be declared a **cell/area zone** (purpose `cell_zone`). It is not a source of anything; it records that a combined L1/L2 segment is a deliberate zone, and closes `flat_control_segment` for it (VLAN buttons: Management / Engineering / Cell/area zone / Unmark; the finding's Fix offers it too).

Re-declaring a network, host or VLAN with another purpose or role updates it. The identical declaration again is a 409.

The active baseline also counts, as IP **or** CIDR:

- `admin_ws` and `jump_host` rows are management sources.
- `engineering_ws` rows are engineering sources.

Consequence: an engineering workstation already in the baseline is no longer flagged for SSH, HTTPS or RDP to L0-L2 equipment.

## How each check uses the declarations

| Check | Row | Sources approved |
|---|---|---|
| `mgmt_access_from_wrong_zone` | 5.1 | Management or engineering (the destination is OT). Runs once any source exists. |
| `session_mgmt_from_non_admin` | 5.5, 9.5 | Management; engineering too when the destination is L0-L2. Fail-open (everything flagged) while nothing is declared. |
| `auth_from_non_admin_host` (real time) | 5.5, 9.5 | Management only (this is a firewall admin login). Open findings whose source becomes covered are closed by the re-check. |
| `mgmt_access_not_restricted` | 2.5 | All approved sources count as ONE zone. |
| `rule_mgmt_wrong_zone`, `chain_mgmt_wrong_zone` | 5.1 | A permit whose source is entirely inside management or engineering networks / trusted hosts, or whose source zone is declared a management or engineering zone. |
| `config_mgmt_not_restricted_to_mgmt_zone` | 5.1 | Management only. An interface with HTTPS/SSH admin access must be a management zone: declared by name, VLAN or subnet, or, with no declaration, named / aliased / zoned mgmt, management or admin. An engineering zone does not satisfy it. One finding per interface, judged from the stored interfaces, so declarations apply without a re-upload. |
| `config_admin_trusthost_outside_mgmt` | 9.5 | Management only. Each admin trusted host must lie inside the management networks / trusted hosts. Judged only once a management network, host or VLAN is declared. |
| `unauth_ot_write` (real time), `unauthorized_industrial_write` (PCAP) | 8.4 | Declared engineering sources, in addition to the baseline's `engineering_ws` / `hmi`. The re-check closes open write findings whose source is now approved, including captures flagged fail-open before the baseline was loaded. |

Name keywords stay **suggestions** for the network checks:

- mgmt, admin, OOB suggest management.
- engineering, EWS suggest engineering.

An interface called "mgmt" is not trusted as a source until confirmed. An interface declared neither, or engineering, also loses its `is_mgmt_only` flag, so topology and access-path analysis stop hiding a routed interface the name heuristic mislabelled.

## Fixing findings from the console

**Findings page.** An open finding of the checks above has a "Fix with a management / engineering declaration" section (`GET /management/fix-options?finding_id=`). The first option is marked suggested:

| Finding | Options offered | Suggested first |
|---|---|---|
| Access toward OT equipment (`mgmt_access_from_wrong_zone`; `session_mgmt_from_non_admin` with an L0-L2 destination; rule / chain findings) | Engineering and management options | Engineering. A DMZ source suggests jump host first. |
| Industrial writes | Engineering only | Engineering workstation |
| Firewall admin login, interface admin access, trusthost | Management only | Management |

Option types:

- the source as a trusted host;
- the network it sits on;
- its VLAN;
- the rule's source zone, reclassified;
- the interface or its FortiOS zone (the label names the subnet that becomes a network of that purpose).

One click declares, re-runs the affected checks and reports what closed.

**Mgmt & Engineering page.** Shows:

- declarations with their purpose, with Remove;
- an add form (kind, purpose, role);
- name-based suggestions with their purpose, to confirm;
- every VLAN the site knows, with Management / Engineering / Unmark;
- every firewall interface with admin access, its classification, and Management / Engineering / Neither / Clear;
- the effective management and engineering sources.

**Re-check.** Every change re-runs `recheck`:

1. the two config checks for every firewall of the site;
2. the real-time and write-finding closure above;
3. a **targeted** periodic run (`run_periodic_reviews(only=...)`) of the five management reviews.

The response carries the open counts per check, before and after. Removing a declaration brings the findings back: config findings re-open in place, and periodic ones are raised again.

## VPN user groups

The same page lists every SSL-VPN user group (and user) named by a tunnel-sourced policy (`groups` / `users` / `fsso-groups`), per firewall, with its policies. Classify each one:

| Category | Meaning | Effect on `vpn_direct_to_ot` |
|---|---|---|
| IT / own staff | the site's own IT or OT staff | SR 1.13, SR 5.2, SR 5.1 |
| Vendor / third party | vendor, integrator, contractor | adds IEC 62443-2-4 SP.07 |
| Other | anything else | SR 1.13, SR 5.2, SR 5.1 |

- `vpn_direct_to_ot` is raised **once per VPN policy chain and user group**, so each group is its own finding; its title shows the category, "guessed" or "unclassified".
- Without a classification the category is guessed from the name (vendor / 3rd / third / contractor / supplier / integrator / partner = vendor; IT..., OT..., staff, employee, corp, internal, helpdesk = IT), and the finding says it was guessed.
- A classification on one firewall wins over a site-wide one (the finding's Fix buttons make site-wide ones; the page's buttons classify per firewall).
- Classifying re-runs `vpn_direct_to_ot`: the open findings keep their id and change title and references. It does not close them - the access itself is still to be fixed.
- Severity stays critical for every category.

Related config check `config_vpn_shared_access` (low; SR 2.8, SR 1.1; row 4.3): two or more VPN user groups get their addresses from the same tunnel pool (group -> portal through `config authentication-rule`, else `default-portal`; portal -> `ip-pools`, else `tunnel-ip-pools`, else the factory pool). Their sessions cannot be told apart in the capture or downstream logs. Fixed by giving each group its own portal and pool.

## API

| Method | Path | |
|---|---|---|
| GET | `/management/networks` | Declarations, interfaces (`purpose`), VLANs (`purpose`), suggestions (`purpose`), effective sources (`purpose`), per site. |
| POST | `/management/networks` | Body `{kind, purpose?, cidr?, role?, vlan_id?, firewall_id?, name?, is_management?, label?, note?, created_by?, finding_id?, recheck?}` returns 201 `{declaration, created, recheck}`. Errors: 422 / 404 / 409. With `finding_id` and no site, the finding's site is used. |
| DELETE | `/management/networks/{id}` | Returns `{deleted, key, recheck}`. |
| GET | `/management/fix-options?finding_id=` | Options ready to POST. |
| POST | `/management/recheck` | Re-runs the affected checks. |
| GET | `/vpn/groups` | VPN user groups per firewall `{name, firewall_id, firewall_name, policies, category, category_source, declaration_id, guess}`, the classifications, the categories. |
| POST | `/vpn/groups` | Body `{name, category, firewall_id?, note?, created_by?, finding_id?, recheck?}` returns 201 `{declaration, created, recheck}`. Re-classifying updates (created false); unchanged is 409; bad category 422; unknown firewall / finding 404. |
| DELETE | `/vpn/groups/{id}` | Removes a classification (back to the guess); `{deleted, key, recheck}`. |

The PDF report lists the declarations, with their purpose, under Firewall Inventory ("Declared Management & Engineering Networks").

## Model

Table `management_networks`:

| Column | Notes |
|---|---|
| `id`, `site_id` | |
| `kind` | subnet / host / vlan / name |
| `key` | unique per site |
| `purpose` | management / engineering |
| `cidr`, `role`, `vlan_id`, `name` | |
| `firewall_id` | FK `firewalls`, ON DELETE CASCADE |
| `is_management` | false = neither |
| `label`, `note`, `finding_id`, `created_by`, `created_at` | |

`firewalls.admin_trusthosts` (JSON, from `config system admin`) is kept so trusthosts can be re-judged without a re-upload.

Migrations: `d2e3f4a5b6c7` (table and column), `e3f4a5b6c7d8` (`purpose`) and `a6b7c8d9e0f1` (`vpn_user_groups`: site, key, name, firewall, category it / vendor / other). Code: `app/parsers/mgmt_networks.py`.

## Limits

- VLAN ids are site-wide; a VLAN declaration does not name a switch. Hosts are placed on a VLAN by the MAC-table / subnet inference that sets `Host.vlan`.
- A VLAN whose subnet is not on a firewall VLAN interface contributes only its hosts, not a subnet.
- Engineering is judged by destination level (L0-L2), not by protocol. An EWS's SSH to an L3 historian is management, and needs a management source.
- `created_by` is free text until authentication exists (A-01).
