# IACS Monitor - how to use it

A task-by-task guide for the operator. The README is the reference (every route, input format,
environment variable and check); this manual tells you what to do, in what order, and what each
page is for. Version 2026.10.09.38.

## Contents

1. [What the application does](#1-what-the-application-does)
2. [Getting started](#2-getting-started)
3. [The console](#3-the-console)
4. [Building the picture of a site, step by step](#4-building-the-picture-of-a-site-step-by-step)
5. [Working the findings](#5-working-the-findings)
6. [Firewall rules: devices, shadowing, reachability, access review](#6-firewall-rules-devices-shadowing-reachability-access-review)
7. [IEC 62443 zones, conduits and security levels](#7-iec-62443-zones-conduits-and-security-levels)
8. [Reports and exports](#8-reports-and-exports)
9. [Routine operation](#9-routine-operation)
10. [Troubleshooting](#10-troubleshooting)
11. [Glossary](#11-glossary)

---

## 1. What the application does

IACS Monitor is a **passive** IEC 62443 / ISA-99 compliance monitor for OT networks. It never
touches the network: you give it what you already have - firewall configurations, firewall and
syslog logs, packet captures, switch command outputs, ARP / MAC tables and inventory or baseline
spreadsheets - and it:

- places every host and every firewall interface on a **Purdue level** (L0 process ... L5 enterprise,
  with L3.5 as the DMZ);
- checks the firewall rules, the observed traffic, the hosts and the device configurations against
  the **IEC 62443-3-3 system requirements** (SR), the OT firewall review checklist rows and the
  CIS-style FortiGate hardening points;
- raises **findings** (critical ... info), each with the requirement, the checklist row, the
  foundational requirement (FR) and security level (SL) it belongs to, the evidence, and a
  "Why this was flagged" explanation with the way to fix and verify it;
- lets you document **IEC 62443-3-2 zones and conduits** with their target, capability and achieved
  security levels, and judges the findings against them;
- produces the **compliance report** (PDF) and the findings workbook (xlsx) per site.

Everything is kept per **site** (a plant or facility). Nothing is sent anywhere; nothing is
changed on any device.

## 2. Getting started

### Install

**Docker (recommended).** With the image loaded or built (`docs/docker-install.md`):

```bash
docker compose up -d          # console at http://127.0.0.1:8000/ui, data on the volume iasc_data
```

**Bare metal / VM.** Unpack the install tarball and run `sudo bash install.sh` (installs to
`/opt/iasc_monitor`, creates the `iasc` user and a systemd unit bound to `127.0.0.1:8000`).
`systemctl status iasc_monitor` and `journalctl -u iasc_monitor -f` manage it.

**Development checkout.** `python3.11 -m venv .venv && . .venv/bin/activate`,
`pip install -r requirements.txt`, `alembic upgrade head`, `uvicorn app.main:app --port 8000`.

There is **no login**: anyone who can reach the port can read and upload. Keep it on the
loopback address or a trusted management network, or put an authenticating reverse proxy in front.

### Open the console and create the first site

Open `http://<host>:8000/ui`. A fresh installation has **no site**: click **+ New site** in the
sidebar (or on the Upload Data page), give it a name (the code is derived, e.g. `plant-a`). Every
upload and every page works on the site selected in the sidebar.

`/docs` is the interactive API reference and `/health` the health check, should you need them.

### Try it with the sample data

`sample_data/` holds a FortiGate config, a Cisco config, a PCAP, syslog files, switch outputs and
baseline CSVs. Upload them from **Upload Data** in the order of section 4, or seed a complete demo
database with `python tests/ui_demo_server.py --db /tmp/demo.db --port 8765` (development checkout).

## 3. The console

The sidebar is organised by task:

| Group | Page | Use it to |
|---|---|---|
| **Site** | selector | Choose the plant you are working on. Every page shows that site only. |
| Ingest | Upload Data | Upload every input (section 4). |
| Ingest | Devices | See the log-sending devices registered per site, map unknown devices, resolve serial / site conflicts. |
| Monitoring | Sites overview | The read-only roll-up over all sites (open findings by severity, last upload / review, PDF per site). |
| Monitoring | Findings | Work the findings (section 5). |
| Topology | FW Topology Builder | Label firewall interfaces with Purdue levels, link firewalls, assign captures to interfaces. |
| Topology | Host Topology | Hosts on their Purdue lanes; drag a host to another level; multi-homed devices in red. |
| Topology | Network Topology (under Host Topology) | The network as it physically is: lanes per subnet / VLAN, hosts coloured by function with their observed conversations (↔ badge), what separates the lanes (firewall, routing switch, flat), and an egress lane with every destination outside the site (Internet, then the corporate side) and who reaches it. For flat networks that route through a firewall. |
| Topology | Firewall Ports (under Host Topology) | Each firewall as its front: ports in config order, the subnet on each port and the VLAN sub-interfaces riding on it (tag, network, level, zone, alias, hosts). Hover a port: the other ports light up with the services the rules permit (`tcp/22`, `ALL`); click pins the policy table. |
| Topology | External comms | What talks to the Internet and which external flows are approved. |
| Topology | Firewall Devices | Every uploaded firewall: boundary, rules, NAT, VPN policies, the stored configuration. |
| Topology | Mgmt & Engineering | Declare management / engineering networks, trusted hosts, VLANs. |
| Compliance | Reachability | Which Purdue level can reach which, through what, and a host-to-host path lookup. |
| Compliance | Access Review | Every path the rules allow between levels, with the traffic seen on it; classify and select for the report. |
| Compliance | Zones & Conduits (+ Subnets & Zones) | IEC 62443-3-2 zone and conduit documentation; Purdue level declarations per subnet. |
| Compliance | Shadow Rules | Shadowed, duplicate and conflicting policies. |
| Compliance | Attestation | Zone-documentation attestation (checklist 1.1-1.6) with proof files. |
| Assets | Inventory | The asset inventory: edit, classify, approve, import / export CSV. |
| System | Reports & Diagnostics | The PDF (LRQA or public layout), the report details (client, contacts, revisions), the findings workbook, the checks in the report, the review schedule, diagnostics. |

Conventions that hold everywhere: clicking a row opens its detail panel **without** moving the
list; a **⚑ n** badge means "n open findings about this object - click to edit them"; a **?**
button opens "Why this was flagged"; a side **drawer** (Escape closes it, focus returns to where
you were) opens an asset, a policy's findings or a firewall configuration over the current page.

## 4. Building the picture of a site, step by step

The order matters: the firewall configuration gives the networks and levels that everything else
is judged against. Reviews run automatically after each upload (see section 9), so findings
appear as you go.

### 4.1 Upload the firewall configuration(s)

**Upload Data → FortiGate** (output of `show full-configuration`) or **Firewall Config** for
Cisco IOS / ASA, pfSense `config.xml` and PAN-OS (XML or `set` format; choose the vendor).

- **Firewall name**: how the device will be called everywhere (defaults to the config hostname).
- **Boundary (from / to level)**: the Purdue boundary this firewall enforces, e.g. from 3.5 (DMZ)
  to 3 (site operations). It is only a stand-in until you label the interfaces (4.2).
- FortiGate only: *Generate findings* runs the configuration checks (`config_*`) at upload;
  *HA peer* names an already uploaded firewall this one is the HA partner of.

Re-uploading a firewall's config **replaces** its rules, interfaces and NAT, re-runs the
configuration checks, closes the configuration findings that no longer reproduce, and keeps the
new text as the stored configuration (passwords, keys and SNMP communities are masked before it is
stored). The stored text is what *Config* on the Firewall Devices card and *Configuration lines*
on a finding show.

### 4.2 Label the interfaces (FW Topology Builder)

> Label the wireless VLAN and SSID interfaces too: the wireless checks (`config_wireless_in_ot`, the
> pre-shared-key and WEP severities) decide "in OT" from the label of the interface or VLAN an SSID
> lands on, as every placement check does. Unlabelled SSIDs are listed on the configuration evidence
> page but not flagged.

This is the most important step: **interface labels decide the levels**. For each firewall, set
the Purdue level of every interface / zone / VLAN sub-interface that matters (the page suggests
levels from names, addresses and traffic). An interface's level applies to every host on its
network (hosts you classify by hand, or subnets you declare, keep their own). Unlabelled sides
are reported as "direction unverified" and not judged.

Selecting an interface also shows **Settings from the config** - its stored configuration block
as a table (type, VLAN id and parent, IP, `allowaccess` with cleartext management protocols in
red, role, alias, DHCP ...; Cisco: `nameif`, `security-level`, `ip address`, `shutdown`, ACL
bindings) with the raw lines and *Open in config* - so you can label it without opening the
device.

Also here:

- **Link firewalls**: when two firewalls sit one behind the other (series), confirm the link and
  the upstream chain; otherwise two firewalls on the same level pair are treated as alternatives.
  HA clusters and paired firewall sets (in series) are declared here too, as firewall groups.
- **Disabled interfaces** are hidden; *Show disabled interfaces* lists them greyed.
- **Captures**: assign each PCAP to the interface (or network) it was taken on so its hosts land on
  the right side (4.3).

### 4.3 Upload packet captures

**Upload Data → PCAP** (`.pcap` / `.pcapng`, up to 50 MB each, uncompressed). The capture is
parsed for Modbus, S7, DNP3, ENIP/CIP, PROFINET, SMB, Telnet, DNS, NTP and the other
protocols the checks know; hosts and conversations are created or updated. Then set the **capture point** (the
firewall interface or the networks the SPAN port saw) in the upload result or on the FW Topology
Builder: it tells the engine which side of which firewall the traffic was on.

### 4.4 Upload logs and register the devices

**Upload Data → Syslog / FortiGate logs** (FortiOS key=value or CEF, ASA, pfSense, PAN-OS;
`vendor_hint=auto` detects them). Log lines are routed to the site of the **device that sent
them**, identified by serial first, then by device name:

- A device that is not registered anywhere has its lines **held** (no findings) until you map it.
  Tick *Map unknown devices to <site>* on the upload, or use **Devices → Unmapped devices → Map
  to site**; the held lines are replayed.
- A line whose serial or site disagrees with the registry is a **conflict**: resolve it on the
  Devices page (*Same device* for a replaced unit, *Different device* with its site, *Add as HA
  member*).

Real-time checks (admin logins, auth failures, blocked cross-zone attempts, rule hits ...) run as
each line is stored; rule-hit logs also feed "last matched" on the rules.

### 4.5 Upload switch and L2 data

> FortiLink-managed FortiSwitches need no separate upload: the FortiGate configuration carries
> them, and the switches, their ports, VLANs and port-security policies appear with the next
> FortiGate upload. A standalone FortiSwitch (not FortiLink-managed) is uploaded here as
> *FortiSwitch (standalone)* with its `show full-configuration`. Upload the switches' MAC tables
> so the unused-port review knows which ports are in use.

**Upload Data → Switch** (Cisco running-config, `show vlan brief`, `show cdp/lldp neighbors
detail`; HP/Aruba running-config and `show lldp info remote-device`), **MAC table** (`show mac
address-table`) and **ARP** (Cisco, Linux, Windows). They give hosts their real VLAN, link hosts to
switch ports, infer roles from neighbours and - for a Cisco routing switch - add it as an
enforcement point beside the firewalls.

### 4.6 Upload baselines and the asset inventory

**Upload Data → Baseline CSVs**: the approved communications matrix (`src`, `dst`, `dst_port`),
the approved hosts (`ip`, `role`), the reviewed policies (`policy_id`) and the **asset inventory**
(`ip` or `mac`, plus hostname, device type, Purdue level, zone, VLAN, SL-C). A baseline has a name
and the active one is what the checks compare against.

For an inventory export with its own column names use **Inventory → Import CSV…**: it previews
the file, suggests a field for every column, lets you pick or ignore each one, lists the rows it
would reject, and can save the mapping for the site so the next export maps itself.

### 4.7 Classify the hosts

Automatic classification uses the interface labels, the protocols a host speaks, its VLAN, LLDP
neighbours and the inventory. Correct it where it is wrong:

- **Host Topology**: drag a card onto another level lane (the confirmation bar names the move;
  every address of the device moves, the device type is kept). Drop it on *Unclassified* to pin
  it without a level, or to return a hand-set host to automatic classification.
- **Inventory**: set device type, Purdue level, zone, SL-C and owner fields on the record;
  *Approve* marks the host as known (closes `unknown_device`). A host that is not an asset to
  track (a scanner, a broadcast or virtual address, a visitor device) can be **excluded from the
  inventory** with a reason: it leaves the Inventory list and export only - it stays on Host
  Topology (marked "not an inventory asset"), Reachability, Access Review and in the findings -
  and `unknown_device` treats it as reviewed. The Inventory filter *Excluded* lists them, with
  *Include in the inventory again*.
- **Network Topology**: see the network by subnet / VLAN rather than by level - which functions
  share a lane ("mixed functions"), which lanes are one flat layer-2 segment, and whether a
  firewall, a routing switch or nothing sits between lanes that talk; *Declare…* on a lane records
  its Purdue level / zone, the first step from a flat network to the Purdue view. With several
  firewalls in the site, pick one in the selector: its lanes are outlined and the connections panel
  shows its rules.
- **Firewall Ports**: the physical picture of a firewall - which subnet sits on which port, which
  ports carry VLAN tags and with what subnets (aggregates name their members, the WAN port is the
  egress leg). Hover a port to see what the enabled policies permit to and from the other ports as
  services (`tcp/502`, `tcp/22` in red for cleartext / management, `ALL` in amber); click to pin the
  table with the policy numbers (each opens the policy on Firewall Devices) and how often a capture
  actually used the service. Permits only - what is allowed, not what is denied.
- **Subnets & Zones**: declare a Purdue level and zone name per subnet; every host on it follows.
  The *Classify level / zone…* button on a firewall rule's source / destination hover does the
  same for the addresses in that rule.
- **Mgmt & Engineering**: declare the management networks, engineering networks, trusted admin /
  jump / engineering hosts and VLANs. Management-protocol and engineering-access findings are
  judged against these.

Device types include PLC, RTU, HMI, historian, engineering workstation, site / enterprise DNS and
NTP servers, jump host and so on; each carries the level it is expected at.

**Multi-homed devices** (one MAC with addresses on two subnets) are shown as red cards on Host
Topology with a dashed *DMZ bypass* link when the addresses straddle the IT / OT boundary.

### 4.8 Run the reviews

Reviews run after every upload and on the schedule (Sundays 02:00 UTC by default). To run them
now: **Findings → Run reviews now** or **Reports & Diagnostics → Run periodic reviews**. A full
review closes the findings it no longer reproduces ("Auto-resolved") - acknowledged and real-time
findings are never auto-closed.

## 5. Working the findings

### The list

**Findings** lists the selected site's findings, most severe first. Filter by status, severity,
category, check, device, SR / FR, target SL, zone SL-T, conduit documentation, or free text; page
through them or step with *Prev* / *Next*. The summary cards at the top count by status, severity,
category and security level. Findings of checks you left out of the report (section 8) are hidden
unless you tick *Show findings of excluded checks*.

### The detail panel

Click a finding. The panel shows the title, severity (and, on a documented conduit that covers the
flow, the lowered shown severity with the reason), the SR / FR / SL / checklist row, the check, the
device, the IEC zone judgement, when it was created and last seen and how often, then:

- **Edit asset** - for a finding about a host: opens the asset in the side drawer (inventory
  fields, Classify, the host's other findings). Saving there re-runs the reviews so the findings the
  change fixes close.
- **Configuration lines** - for a finding about a firewall configuration or rule: the stored
  configuration lines behind it (the policy block, the interface / admin / VIP / IPsec block, the
  section the check reads, or the Cisco rule line), with line numbers. *Open in config* opens the
  whole configuration in the drawer on those lines, highlighted.
- **Why this was flagged** - what was found, why it matters, the requirement, how to resolve, how
  it closes, how to verify by hand. *All evidence fields (raw)* shows the detail JSON.
- One-click fixes for management-protocol and VPN-group findings, where they apply.
- **Update status** (below).

### Status lifecycle

| Status | Meaning | Notes |
|---|---|---|
| open | Needs action | A re-detection updates *last seen* and the count; a worse re-detection escalates in place. |
| acknowledged | Seen, being handled | Needs your name. Recurrences are absorbed; an escalation re-opens it with a note. |
| closed | Resolved | If the condition comes back a **new** finding opens. Auto-resolve closes findings a full review no longer reproduces. |
| false positive | The finding is wrong | Needs your name and a **reason**. Never raised again; listed in its own section of the exports and the PDF. |

Notes are appended with a time stamp and never overwritten; findings are never deleted (the audit
trail).

### Findings next to the objects they are about

The same inline editor (status, name, notes, reason) is behind the **⚑** badges on the Inventory
list and asset panel, the Host Topology host panel, each Firewall Devices policy line, and the
zones and conduits on Zones & Conduits - so you can fix the object and update its findings in one
place.

## 6. Firewall rules: devices, shadowing, reachability, access review

**Firewall Devices.** One card per uploaded firewall with its boundary, interfaces / zones
(aliases in grey), counts of active, disabled, NAT and VPN policies, and the buttons:

- *Rules* - one line per policy (sources, destinations, services together; click to expand the
  rows). Hover a zone name for its networks and hosts; hover a source / destination for every
  address with the inventory host behind it and *Classify level / zone…*. The ⚑ badge opens the
  policy's findings.
- *Disabled* - policies flagged for removal; *NAT* - VIPs / port forwards and source NAT; *VPN* -
  policies with a tunnel as a side, with the user groups they name.
- *Config* - the last uploaded configuration (masked), with folding sections, find (Enter = next
  match), go to line and download.
- *Edit boundary* - the stand-in levels used until the interfaces are labelled.

**Shadow Rules.** Per device, the policies that can never match (fully shadowed), that are
partly covered, duplicates, and shadowed *deny* rules (a conflict). One card per policy pair;
*Show the row pairs* gives the detail. They are also findings (`shadow_rule`) and a PDF section.

**Reachability.** The level-to-level matrix (allowed / partial / blocked) with the enforcement
points on each pair, the paths per cell, and a host-to-host lookup that applies NAT. It uses the
interface labels, the firewall chain and the captures' carrier.

**Access Review.** Every path the rules allow between Purdue levels, with the traffic actually
seen on it (observed / not observed / blocked), its flags (cleartext, management protocol,
industrial write ...), and your classification: approved, to remove, to restrict, investigate, with
a note and your name - which drives the report. Similar rows roll up into one line (toggle *Roll
up similar paths*); the bulk bar sets a note or classification on many rows.

**External comms.** The external destinations seen from the site; approve a flow (with a reason)
so it stops raising Internet-egress findings - except from OT devices: "no OT device should have
direct access to the Internet" always applies.

## 7. IEC 62443 zones, conduits and security levels

**Subnets & Zones** (under Zones & Conduits) is the Purdue side: a level and zone name per subnet,
used by the checks.

**Zones & Conduits** is the IEC 62443-3-2 documentation. It never changes a finding or a level;
it adds the judgement:

1. **Add zones** - name, description, **SL-T** (target) and, once assessed, **SL-A** (achieved);
   levels run SL0 - No Requirements ... SL4 - Advanced Resources. Import them from Subnets & Zones
   or from the FortiGate zones to start.
2. **Add members** - hosts, subnets, firewall interfaces / VLAN sub-interfaces, FortiGate zones.
   Hosts carry their own **SL-C** (capability, from the inventory); the page flags members below
   the zone's SL-T.
3. **Document conduits** between zone pairs with SL-T / SL-A and attach the **firewall rule
   numbers** that implement them (chips with a hover card: source, destination, allow / deny,
   services). The policies found between the two zones that are not attached are marked.
4. Read the results: zone pairs that communicate **without** a documented conduit, documented
   conduits with their firewalls and observed traffic per direction, firewalls' SL-C against the
   conduits they carry, hosts in no zone. Each device finding shows its zone, whether the check
   applies at that zone's SL-T, and whether its path is inside one zone, over a documented conduit
   or undocumented.

**Attestation** records the zone-documentation attestation (checklist rows 1.1-1.6) with a proof
file and keeps the history; the PDF reports its state.

## 8. Reports and exports

**Report layouts (2026-10-18).** *Report layout* on the Reports page offers two PDFs. The **LRQA compliance
report** (default) follows the technical-report template: cover (Prepared For,
Project, Author, Date), Contents, Distribution List, Revision History, Engagement Particulars
(background, scope, constraints, finding summary), Findings (one row per check), Analysis (one entry
per check) and an Appendix with the supporting sections. Fill in **Reports & Diagnostics → Report
details** (client, project, author, version, classification, the client points of contact and the
assessor team for the distribution list - as many rows as needed -, the revision history, the
assessment window / constraints) - it is saved per site and printed on the
cover and the first pages; until then the report uses the site name and the defaults. The **public compliance
report** is the previous layout: cover table, executive summary, findings by area with the write-ups.

**What the PDF says per check (2026-10-17).** The findings part of the report is written once per
check: the *concern* (what was observed), *why it is a finding*, the *remediation*, for FortiGate
configuration checks a *FortiOS example* with the settings that remediate it - filled from the
finding where it names a policy, interface or account - and *when it closes*. Under the write-up one
table lists every affected firewall or device of the site with the policies, interfaces, VLANs,
subnets, accounts and hosts the findings name, the highest severity and the status counts. The
checklist numbers, SR, FR and SL are no longer printed; each check carries its references instead
(IEC 62443-3-3 SR with its title, IEC 62443-2-1 / 3-2 where it applies, NIST SP 800-82r3 with the
SP 800-53 controls, and the CIS FortiGate Benchmark topic). The same references and FortiOS example
show in the console under "Why this was flagged".

**Reports & Diagnostics → Compliance report (PDF).** Options: target security level (SL0-SL4 or
all: checks whose requirements only apply above the target are left out and marked), *Ignore the
check selection*, *Include closed findings* (their own section), zones on / off, one site or the
all-sites roll-up, and *Report layout*. The LRQA compliance report is described above; the public
compliance report has the executive summary (severity × status and per-area totals), the findings
by area and check with the write-ups, the false positives, closed findings, the checks excluded, the
attestation, zones and conduits, the firewall inventory, shadowed and redundant rules, the access
review, the check coverage (FINDINGS / PASS / NOT EVALUATED / no data per check, with why), the
FortiGate configuration evidence and the control mapping.

**Checks in the report.** Every check grouped by source (FortiGate configuration, firewall rules,
access paths, zones, logs, traffic, switches, network) or by checklist section, with tri-state
group boxes, search, a reason and your name. Deselected checks are left out of the PDF and listed
in it; their findings are hidden throughout the console unless you ask for them. Saved per site.

**Findings workbook (xlsx).** Export the site's findings (optionally closed / excluded ones),
edit **Status**, **Name**, **New note** and **False-positive reason** in Excel, then *Preview
changes* and *Apply*: each changed row goes through the same rules as the Findings page, refusals
are listed per row, and importing the same file twice changes nothing. Use it for a review round
with people who do not use the console.

**Audit checklist report (xlsx → PDF / CSV).** For the audit you run by hand against the ISA/IEC
62443 Master Audit Checklist workbook: fill the yellow columns in Excel (Status, Maturity Level,
Finding / Observation, Evidence Reviewed, Severity, Recommendation, Owner, Target Date), upload the
workbook on this card, fill in **Prepared for**, the **Author**, the **Date of the report**, the
**Client points of contact** and the **LRQA consultants** (add as many rows as needed; the card is
pre-filled from *Report details* and nothing you type here is saved), *Check workbook* to see the
counts and the finding list (and notes such as a finding without a status), then *Download report
(PDF)* or *Download findings (CSV)*. The command line `python generate_audit_report.py CHECKLIST.xlsx`
asks the same questions on the terminal (or takes `--client`, `--author`, `--date`, `--poc`,
`--consultant`; `--no-prompt` skips the questions). Each checklist
row becomes one report finding: the check title is its title, the audit check its details, the domain
its area, and your observation, evidence and recommendation are printed as written, with the status,
maturity, severity, owner and target date. The PDF has the same front pages as the compliance report
(cover, distribution list, revision history from *Report details*), a compliance-by-domain table, one
analysis page per finding and an appendix with every check's status. *Findings* chooses which rows
are reported (non-compliant / partially compliant and recorded findings; every assessed check; every
check); *Order* sorts by severity or keeps the checklist order. Nothing is stored on the server.

**CSV**: findings (`/findings/export`), the asset inventory (Inventory → Export), zones and
conduits (Zones & Conduits → export). The command line `python generate_report.py` produces the same PDF from
the database (see README → Compliance report).

## 9. Routine operation

- **Re-upload configurations** whenever they change; the rules, NAT and configuration findings
  follow, and the stored configuration is replaced (latest only).
- **Feed logs** regularly (FortiAnalyzer / syslog exports); keep the Devices page free of held
  and conflicting lines.
- **Reviews**: after every upload (`IACS_REVIEW_ON_UPLOAD`) and on the schedule
  (`IACS_REVIEW_SCHEDULE`, pause / resume on Reports & Diagnostics). `/diagnostics` shows the last
  run's failures, escalations and auto-resolves.
- **Backups**: Docker `docker compose exec iasc-monitor python backup_db.py` (online backup to
  `/data/backups/`); bare metal: copy the `.db` with its `-wal` / `-shm` files or checkpoint
  first. PostgreSQL is supported (`IACS_DATABASE_URL`).
- **Upgrades**: load the new image and `docker compose up -d` (the entrypoint runs the
  migrations), or unpack the new tarball and run `install.sh` again (it keeps the database and
  `.env`). Each release's upgrade notes are at the end of `docs/code-review-remediation.md`.
- **Deleting** (sites, devices, findings) is off unless `IACS_ENABLE_DELETE=true`.
- **Retention**: held log lines of unmapped devices are purged after 30 days
  (`IACS_UNMAPPED_RETENTION_DAYS`).

## 10. Troubleshooting

| Symptom | Cause / what to do |
|---|---|
| Upload answers **413** | Over the size limit (PCAP 50 MB, configs / CSV / syslog 10 MB) or the rule-row budget (`IACS_MAX_RULE_ROWS_PER_INGEST`). Split the file. |
| Upload answers **415** | Compressed file (gzip, zip ...) or a PCAP without a pcap/pcapng header. Decompress first. |
| Upload answers **422 "unknown site"** | Every non-log upload needs the site; pick it on the form. |
| **409 "No site exists yet"** | Create the first site (+ New site). |
| Log lines produce no findings | They are held: the device is unmapped or in conflict (Devices page). |
| A check shows **NOT EVALUATED** in the PDF | Its review has not run completely since the last upload: run the reviews, then rebuild the report. |
| A rule is "direction unverified" | One side's interface has no Purdue label (FW Topology Builder). |
| "No configuration text is stored" | The config was uploaded before this version kept the text; upload it again. |
| Two firewalls both seem to allow a path | They are treated as alternatives; declare the chain / link / paired group if they are in series. |
| The console says it was opened from disk | Load it from the server (`http://host:8000/ui`), never as a `file://` page. |
| Findings disappeared from the list | Their check is deselected under *Checks in the report*; tick *Show findings of excluded checks*. |

## 11. Glossary

- **Purdue level**: L0 process (sensors / actuators), L1 basic control (PLC / RTU), L2 supervisory
  (HMI / SCADA), L3 site operations (historian, engineering, site DNS / NTP), L3.5 DMZ, L4 site
  business, L5 enterprise / remote.
- **Enforcement point**: a firewall (or routing switch) leg between two levels, defined by its
  labelled interfaces.
- **Conduit**: the documented communication path between two zones and the policies that
  implement it.
- **SL-T / SL-C / SL-A**: target, capability and achieved security level (IEC 62443-3-2 / -4-2),
  0 (no requirements) to 4 (advanced resources).
- **FR / SR**: the seven foundational requirements and the system requirements of IEC 62443-3-3
  that each check maps to.
- **Checklist row**: the row of the OT firewall review workbook a check answers (e.g. 3.2 "no
  any/any rules").
- **Finding**: one check result about one object (policy, host, flow, setting), with its evidence
  and lifecycle.
- **Site**: one plant; every record and every page belongs to exactly one.
