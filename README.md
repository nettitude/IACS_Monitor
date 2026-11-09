# IACS_Monitor

IACS_Monitor is an OT/ICS network security monitor. It ingests firewall
configurations, firewall and syslog logs, packet captures, switch data and
audit baselines, then produces **ISA/IEC 62443-3-3 findings** mapped to
the Purdue model (levels 0, 1, 2, 3, **3.5 Industrial DMZ**, 4, 5).

- Stack: Python 3.11, FastAPI, SQLAlchemy 2.x, Alembic, APScheduler, Scapy, reportlab
- Database: SQLite (default, WAL mode) or PostgreSQL (`postgresql+psycopg2://`)
- UI: a single-page console at `/ui` plus five standalone pages, all served by the API itself
- Output: findings (API, CSV export, UI) and an ISA/IEC 62443 compliance PDF

> **Security note:** the API has **no authentication**. The project owner made this decision, and it is the
> first item under [Known limitations](#known-limitations). Run the service only on a trusted network,
> and plan authentication before you expose it more widely.

---

## Contents

Operator guide: **[docs/user-manual.md](docs/user-manual.md)** (what to do, in what order, page by page).

1. [Quick start](#quick-start)
2. [Configuration (environment variables)](#configuration-environment-variables)
3. [Supported inputs](#supported-inputs)
4. [Findings and checks](#findings-and-checks)
5. [Sites (multi-site)](#sites-multi-site)
6. [API reference](#api-reference)
7. [Web UI](#web-ui)
8. [Installation and deployment](#installation-and-deployment)
9. [Database migrations](#database-migrations)
10. [Compliance report](#compliance-report)
11. [Development and testing](#development-and-testing)
12. [Module tree](#module-tree)
13. [Known limitations](#known-limitations)

---

## Quick start

### 1. Install (development checkout)

```bash
python3.11 -m venv .venv && . .venv/bin/activate
pip install -r requirements.txt          # add requirements-dev.txt for tests
```

### 2. Create the schema and run the server

```bash
alembic upgrade head                     # builds ./iasc_monitor.db (or IACS_DATABASE_URL)
uvicorn app.main:app --port 8000
```

You can skip `alembic upgrade head` on a brand-new database. In that case `init_db()` creates the
schema at startup and stamps it at the Alembic head. On any existing database, run the migration
before you start the server. See [Database migrations](#database-migrations).

`IACS_DATABASE_URL` defaults to `sqlite:///./iasc_monitor.db`. The path is relative to the
**current working directory**.

### 3. Open the console

Open `http://localhost:8000/ui` in a browser. The bare host `/` redirects there. Interactive
OpenAPI docs are at `/docs`, and the health check is at `GET /health`.

You can't open `ui/*.html` straight from disk. A `file://` page has origin `null`, so the
browser blocks its API calls. Always load the UI from the server.

### 4. Load the sample data

Upload the samples in `sample_data/` from **Upload Data** in the console, or use curl. Every
non-log upload names the [site](#sites-multi-site) it belongs to (`site=` id, name or code); a
fresh database has one site, **Default** (code `default`):

```bash
B=http://localhost:8000
S=default                                # or create one: curl -H 'Content-Type: application/json' -d '{"name":"Plant A"}' $B/sites
# Firewall configs (tag each firewall with the Purdue boundary it enforces)
curl -F file=@sample_data/sample_fortigate_config.txt "$B/ingest/fortigate-config?site=$S&firewall_name=FW-OT&purdue_zone_from=3.5&purdue_zone_to=3"
curl -F file=@sample_data/sample_firewall_cisco.txt  "$B/ingest/firewall?site=$S&vendor_hint=cisco&firewall_device_name=Corp-FW&purdue_zone_from=4&purdue_zone_to=3.5"
# Traffic and logs (log lines are routed to the site of their device; site= on a
# log upload maps UNKNOWN devices to that site - without it they are held, see Sites)
curl -F file=@sample_data/multi_protocol_sample.pcap "$B/ingest/pcap?site=$S"
curl -F file=@sample_data/sample_syslog_asa.log      "$B/ingest/syslog?vendor_hint=auto&site=$S"
curl -F file=@sample_data/sample_forti_events.cef    "$B/ingest/forti-syslog?site=$S"
# Switch / L2 data
curl -F file=@sample_data/sample_switch_running_config.txt "$B/ingest/switch?site=$S&vendor_hint=cisco&device_name=SW-OT-01"
curl -F file=@sample_data/sample_mac_table_cisco.txt       "$B/ingest/mac-table?site=$S&vendor_hint=cisco&device_name=SW-OT-01"
curl -F file=@sample_data/sample_arp_cisco.txt             "$B/ingest/arp?site=$S&format_hint=cisco"
# Audit baseline (approved communications, approved hosts, asset inventory)
curl -F file=@sample_data/sample_approved_comms.csv  "$B/ingest/baseline/comms-matrix?site=$S"
curl -F file=@sample_data/sample_approved_hosts.csv  "$B/ingest/baseline/approved-hosts?site=$S"
curl -F file=@sample_data/sample_asset_inventory.csv "$B/ingest/baseline/asset-inventory?site=$S"
```

To seed a complete demo database with every sample in one step, run
`python tests/ui_demo_server.py --db /tmp/demo.db --port 8765`. This creates two sites (Plant A,
Plant B), loads every sample through the API into one of them, runs the reviews and serves the
result. Note that it also plants harmless XSS-test strings in
the data.

### 5. Run the reviews and read the findings

```bash
curl -X POST $B/reviews/run                  # all periodic ISA/IEC 62443 reviews, now
curl "$B/findings?status=open&severity=critical"
curl -o findings.csv "$B/findings/export?status=open&severity=critical,high"
curl  $B/findings/summary
curl -o report.pdf $B/reports/compliance.pdf
```

Periodic reviews also run on a schedule (Sundays 02:00 UTC by default; see
`IACS_REVIEW_SCHEDULE`). Real-time checks run as each log event is ingested. FortiGate config
checks run as each config is ingested.

---

## Configuration (environment variables)

The application reads every variable below. No others exist.

| Variable | Default | Read by | Effect |
|---|---|---|---|
| `IACS_DATABASE_URL` | `sqlite:///./iasc_monitor.db` | app/db.py, alembic/env.py, generate_report.py, entrypoint, install.sh | SQLAlchemy URL. For PostgreSQL use `postgresql+psycopg2://user:pass@host/db`. The Docker image sets `sqlite:////data/iasc_monitor.db`, and install.sh writes `sqlite:///<prefix>/iasc_monitor.db` to `.env`. |
| `IACS_ALLOWED_ORIGINS` | *(empty)*, which allows `http://localhost:8000`, `http://127.0.0.1:8000`, `http://localhost:3000`, `http://127.0.0.1:3000` | app/main.py | Comma-separated CORS origins. You only need it when a UI on **another** origin calls the API. The bundled UI is served same-origin at `/ui` and needs no CORS. It is never a wildcard. Exposed headers: `X-Total-Count`, `X-Hosts-Total`, `X-Sessions-Total`. |
| `IACS_REVIEW_ENABLED` | `true` | app/main.py | `0`/`false`/`no`/`off` turns off the background review scheduler at startup (a hard off: the runtime switch below cannot override it). `POST /reviews/run` still works. To pause / resume the schedule **without a restart**, use the console switch (Reports & Diagnostics → Periodic reviews) or `PUT /reviews/schedule`. |
| `IACS_REVIEW_SCHEDULE` | `0 2 * * 0` (Sun 02:00 UTC) | app/main.py | 5-field cron expression, UTC. Misfires are tolerated for up to 1 h. |
| `IACS_SCHEDULER_LOCK` | next to the SQLite file (`iasc_scheduler.lock`), else `<tmpdir>/iasc_scheduler.lock` | app/main.py | `fcntl.flock` lock file. Only the process holding it runs the scheduler, so `--workers N` doesn't run reviews N times. The lock is per host. |
| `IACS_SCAN_SWEEP_HOSTS` | `20` | app/parsers/alert_engine.py | FO-04: addresses a capture source must probe - most of them refused, unanswered or silent to ARP - before `session_scanning_anomaly` reports a host sweep. |
| `IACS_NTP_MIN_CAPTURE_SECONDS` | `3600` | app/parsers/alert_engine.py | FO-11: on captures shorter than this, OT devices that sent no NTP are one informational `ntp_sync` roll-up instead of one finding each. |
| `IACS_MAX_REQUEST_BYTES` | `54525952` (50 MiB PCAP limit + 2 MiB) | app/main.py | Hard cap on any POST/PUT/PATCH body. Larger bodies are rejected with **413** before parsing. |
| `IACS_MAX_RULE_ROWS_PER_INGEST` | `100000` | parsers/common.py (all config parsers) | Most FirewallRule rows one config upload (FortiGate, Cisco/ASA, pfSense, PAN-OS) may expand to, summed over all policies. Each policy's src × dst × service product is checked **before** its rows are built. Over the limit the upload is rejected with **413** and nothing is stored. |
| `IACS_MAX_RULE_ROWS` | `25000` | parsers/firewall_parser.py | Most rows one policy may expand to. Over it, the largest side is stored as a `too-large:<name>` token (counted in `rules_over_limit`). Read at startup. |
| `IACS_PCAP_MAX_PACKETS` | `2000000` | parsers/pcap_parser.py | Most pcap records processed per upload. A 50 MB capture holds at most about 690k minimum-size frames, so this only stops pathological files such as empty-record "pcap bombs". |
| `IACS_PCAP_MAX_NEW_HOSTS` | `20000` | parsers/pcap_parser.py | Most new Host rows one pcap may create. |
| `IACS_PCAP_MAX_SESSIONS` | `200000` | parsers/pcap_parser.py | Most sessions (conversations) one pcap may create or update. |
| `IACS_PCAP_MAX_SECONDS` | `600` | parsers/pcap_parser.py | Wall-clock budget for one pcap ingest, covering the pre-scan and the main pass. |
| `IACS_AUTO_RESOLVE` | `true` | alert_engine.py, forti_config_parser.py | Auto-closes open findings that a successful periodic review, or a FortiGate re-ingest, no longer reproduces. `0`/`false`/`no`/`off` turns it off. |
| `IACS_UNUSED_RULE_DAYS` | `90` | topology_diff.py | A permit rule whose `last_matched` (from logs or the diff) falls inside this window isn't reported as unused. Invalid or negative values fall back to the default. |
| `IACS_UNMAPPED_RETENTION_DAYS` | `30` | app/site_devices.py | Days a held log line of an unmapped device is kept (replayed / discarded lines are purged at the next daily run or `POST /site-devices/unmapped/purge`). |
| `IACS_HA_MAX_MEMBERS` | `4` | app/site_devices.py | B-12: maximum member serials of one HA cluster device (FGCP limit 4; clamped 2-16). |
| `IACS_ENABLE_DELETE` | *(off)* | app/api/routes.py | `1`/`true`/`yes`/`on` turns on the `DELETE` endpoints. Without it they return **403**. |
| `IACS_REVIEW_ON_UPLOAD` | `true` | app/review_trigger.py | Run the periodic reviews of the site after every upload (configs, captures, switch / MAC / ARP outputs, FortiAnalyzer reports, baselines and inventory, capture assignment, baseline activation) in the background; uploads during a run are coalesced into one more run, a run behind the scheduler's lock is retried. The upload response says `"reviews": "queued"`. Live log lines (forti-event / syslog) do not trigger it. `false` = reviews only on the schedule or **Run reviews**. |
| `IACS_SQLITE_FOREIGN_KEYS` | `true` | app/db.py | SQLite `PRAGMA foreign_keys`. `false` is an escape hatch for legacy databases. Delete endpoints cascade explicitly, so they behave the same either way. |
| `IACS_MANUF_FILE` | *(unset: scapy's bundled OUI DB)* | parsers/common.py | Path to a Wireshark/Grassmarlin `manuf` file for MAC-vendor lookup. See [MAC vendor lookup](#mac-vendor-lookup-oui-data). |
| `IACS_SKIP_MIGRATIONS` | `false` | docker-entrypoint.sh | Exactly `true` skips the entrypoint's stamp/upgrade step. |
| `IACS_LEGACY_DB_REVISION` | `0001baseline0` | docker-entrypoint.sh | The revision that an **unversioned** legacy database is stamped at before `alembic upgrade head`. |
| `IACS_HOST` / `IACS_PORT` | `127.0.0.1` / `8000` | install.sh systemd unit only | uvicorn bind address. The app doesn't read these. Edit them in `<prefix>/.env` and restart the service. |

When a pcap limit is hit, processing stops. Everything processed up to that point is committed, and the response reports `"truncated": true` with `truncation` (`limit`, `env_var`, `limit_value`, `records_processed`, `packets`, `hosts_created`, `sessions`), and the server logs a warning. Compressed uploads (gzip, bzip2, xz, zip, zstd, 7z, lz4) are rejected with **415** on every ingest route, as are pcap uploads that do not start with a pcap/pcapng header. The size limits count the bytes actually received.

Test-only knobs: `tests/conftest.py` sets `IACS_DATABASE_URL`, `IACS_REVIEW_ENABLED=false` and
`IACS_SCHEDULER_LOCK` to temporary values before anything imports `app.db`.

---

## Supported inputs

Every upload is a multipart `file` field. Size limits are **50 MB** for PCAP, **10 MB** for
configs, CSV and syslog, and **20 MB** for attestation proofs. Uploads are streamed in 1 MB chunks
and rejected with **413** as soon as they pass the limit. The request-body cap
(`IACS_MAX_REQUEST_BYTES`) applies on top of that.

### Firewall configurations

Every vendor's interfaces (FortiGate `system interface`, PAN-OS `network interface` + zones, ASA `nameif` / `security-level` / `ip address`, pfSense `<interfaces>`) become FirewallInterface rows, so all firewalls get levels, links and an upstream chain on the FW Topology page. NAT is evaluated per vendor: FortiGate and ASA post-NAT, PAN-OS and IOS pre-NAT (an ASA is told from IOS by its config). ASA implicit permits (higher → lower security level from an interface with no inbound ACL) are modelled as `implicit:<from>><to>` rules and reported (`rule_implicit_permit`).

| Vendor | Endpoint | What is parsed |
|---|---|---|
| **FortiGate (FortiOS)** `show full-configuration` | `POST /ingest/fortigate-config` | **Multi-VDOM**: policies, objects and NAT per VDOM; each VDOM is an enforcement point of its own and two VDOMs joined by an inter-VDOM link are evaluated in series (the link is internal, not a zone). SSL-VPN tunnel interfaces and tunnel-pool hosts are L5 (remote) automatically. `system interface`/`zone` → zones and FirewallInterfaces. `firewall address`/`addrgrp` (recursive, with cycle detection) and service objects/groups, including predefined ones. `firewall policy` **and `policy6`** (IPv6), including `internet-service` tokens. **VIP / vip6 / vipgrp** become DNAT rules (a VIP used as a destination resolves to the mapped address), and policy `set nat enable` with **ippool** becomes SNAT. Multi-VDOM backups are flattened (`config global` + `config vdom`), and cross-VDOM name collisions are logged. Runs the FortiOS `config_*` checks unless `generate_findings=false`. Optional `populate_approved_hosts` adds admin trusted-hosts as ApprovedHosts. **FortiLink-managed FortiSwitches** (`switch-controller managed-switch`) become switch rows of the site - ports with native / allowed VLANs, port-security policy, admin state, the FortiLink uplink - and switch VLANs that take the Purdue label of the FortiGate's VLAN interface; the Firewall Ports page names the switches under their FortiLink port; reviews `switch_port_no_nac` and `switch_unused_port_enabled` judge the ports. |
| **Cisco IOS / ASA** | `POST /ingest/firewall?vendor_hint=cisco` | Numbered, named and extended ACLs (sequence numbers, remarks, ASA `extended`/`line N`, standard ACLs, wildcard vs netmask detection, `ipv6 access-list`). Network/service/port/protocol **object-groups** and `object network/service`, nested and expanded src×dst×svc. Interface binding through `ip access-group` / `ipv6 traffic-filter` / ASA `access-group`. **NAT:** IOS `ip nat inside source static|list|route-map`, and ASA object NAT and basic twice NAT. ASA `inactive` is treated as disabled. |
| **pfSense** `config.xml` | `POST /ingest/firewall?vendor_hint=pfsense` | Filter rules (inet/inet6/inet46) with **aliases** resolved, interface-network macros (`lan`, `lanip`, `(self)`) resolved from `<interfaces>`, `<not/>` negation, `<disabled/>`, and the tracker as `policy_id`. **NAT:** port forwards (DNAT) and outbound NAT (SNAT). |
| **Palo Alto PAN-OS** XML or `set` format | `POST /ingest/firewall?vendor_hint=palo_alto` | Security rulebases only, in evaluation order: shared pre, device-group pre, local, device-group post, shared post (**Panorama**). Covers `vsys` and `device-group` scopes. **Address objects/groups** and **service objects/groups** are resolved, and `application-default` resolves to the App-ID's default ports (common App-IDs; unknown ones stay any, noted on the rule). `negate-source`/`negate-destination`, `disabled yes`. **NAT** rules from both formats. |

Common behaviour across all firewall parsers:

- **Disabled rules** are stored with `enabled=false`. Every analysis excludes them (reachability,
  shadowing, rule twins, cross-firewall, diff/unused, config checks), and they are reported by the
  `disabled_rule` check. List them with `GET /firewall-rules?enabled=false`.
- **Negated addresses:** a negated *permit* widens the negated side to `any`, which
  over-approximates exposure, and a note is appended to `raw_line`. A negated *deny* is skipped and
  counted in `rules_skipped_negated_deny`.
- **Canonical `dst_port`:** `any`, `22`, `80,443`, `1000-2000`, `80,443,1000-2000` (ascending,
  merged, no spaces). An unmapped port name becomes `unknown:NAME` and an unresolved object becomes
  `object-group:NAME` / `alias:NAME`. These are **never widened to `any`**.
- IPv6 rules are stored. An IPv6 `any` side is written as `::/0`, so a v6 row never matches an
  IPv4 query.
- Every skip is counted in the response `stats`.
- `/ingest/firewall` accepts `firewall_device_name`, `purdue_zone_from` and `purdue_zone_to`.
  Levels are validated server-side and accept `0`–`5`, `3.5`, `L3.5` or `dmz`.

### Firewall and syslog logs

| Endpoint | Formats |
|---|---|
| `POST /ingest/forti-syslog` | FortiGate/FortiAnalyzer **CEF** (including behind RFC3164/5424 headers, `FTNTFGT*` keys) and FortiOS **key=value** |
| `POST /ingest/syslog?vendor_hint=auto\|fortinet\|cisco_asa\|pfsense\|panos` | All of the above, plus **Cisco ASA/FTD** (106100/106023/106001/106006/106015, 302013–302016, 113004/5, 611101/2, 605004/5, 111008/10, 733100/1), **pfSense/OPNsense `filterlog`** (IPv4/IPv6) and webConfigurator logins, and **PAN-OS CSV** (TRAFFIC, THREAT, SYSTEM, CONFIG). The vendor is detected per line. |
| `POST /ingest/forti-report` | FortiAnalyzer scheduled **CSV** reports (best-header detection, BOM, column variants) |
| `POST /ingest/forti-event` | One FortiAnalyzer event as a **JSON** body (webhook / event handler) |

Every log path normalises events into `FortiAnalyzerEvent` rows and **deduplicates** them with a
`dedup_hash`. If you upload the same file twice, the duplicates are skipped and reported as
`duplicates_skipped`. Each new event then runs the **real-time checks**. Traffic events also stamp
**`FirewallRule.last_matched`** (rule-hit tracking): FortiOS by policy id, pfSense by tracker,
PAN-OS by rule name, and ASA by ACL name or first-match evaluation. `device_name` is the fallback
for lines that carry no hostname.

### Packet captures

`POST /ingest/pcap` accepts pcap and pcapng. For each capture it:

- builds Hosts and 5-tuple NetworkSessions with packet timestamps (IPv4 and IPv6);
- reassembles **IP fragments** and per-direction **TCP streams** (sequence order, retransmits,
  gaps, protocol-aware resync);
- runs **DNP3 transport-layer reassembly**;
- decodes Modbus/TCP (502), S7comm (102), DNP3 (20000), EtherNet/IP + CIP (TCP/UDP 44818),
  PROFINET DCP/RT (EtherType 0x8892) and SMB version detection (445/139, flags SMBv1);
- re-runs Purdue classification and the checklist 8.4 check (unauthorised industrial
  write/program operations) against the approved-host baseline.

Where a host's Purdue level comes from (`classification_source`, strongest first):
the operator (`manual`), a declared subnet zone (`subnet_declared`), an observed
protocol role (`protocol_inferred`), a switch VLAN name (`vlan_inferred`), an
LLDP / CDP role (`lldp_role_inferred`), the vendor OUI (`oui_hint`), and - for a
host with no evidence of its own - the Purdue level of the labelled firewall or
switch interface whose network it sits on (`interface_label`). The interface
label places the host for the level-based checks but does not identify it: it
has no device type, stays an unknown device when it talks an industrial protocol,
and follows the interface when the label changes or is cleared.

The whole ingest is one transaction.

**Capture point (VD-02a).** Name where the capture was taken: `?firewall_id=` (an uploaded
firewall of the site), optionally `&interface_id=` (the port; `any` = several / not known) or
`&capture_networks=10.3.0.0/24,...` for a switch SPAN that is no firewall port. A single routed
frame then identifies the firewall's MAC, so a host behind it is never recorded with that MAC.
Without a firewall the capture is still ingested and flagged *unassociated*; associate it later
with `POST /ingest/pcap/{capture_id}/associate` (body `firewall_id` / `interface_id` /
`capture_networks`) - the capture's hosts are re-attributed. `GET /ingest/pcap/captures` lists
the uploads and their capture points; the Upload page does both.

`POST /ingest/pcap-fw` also records a `PcapCapture`, scores which firewall interface the capture
came from, and asks for confirmation through `POST /ingest/pcap/{capture_id}/confirm`.

### Switch and L2 data

| Endpoint | Formats |
|---|---|
| `POST /ingest/switch?vendor_hint=cisco\|hp\|fortinet` | **FortiSwitchOS** standalone `show full-configuration` (`config switch interface` native / allowed VLANs and `security-mode`, `physical-port` state and description, `switch trunk` uplinks, `switch vlan` names; SNMP communities and `allowaccess telnet` for the hardening checks; FortiLink-managed switches need no upload - they come with the FortiGate backup). Cisco IOS running-config interface blocks, `show vlan brief`, `show cdp neighbors detail`, `show lldp neighbors detail`. A Cisco switch with `ip routing` and routed SVIs becomes an enforcement point beside the firewalls (SVIs, ACLs bound with `ip access-group`, implicit routing permit; SVI levels follow the firewall labels) with the checks `switch_routes_between_zones`, `switch_acl_wrong_direction`, `switch_mgmt_svi_unrestricted` and `switch_dual_gateway`. HP/Aruba (ProCurve CLI) running-config `vlan` blocks, `show lldp info remote-device` (brief and detail). LLDP/CDP neighbours infer host roles. |
| `POST /ingest/mac-table?vendor_hint=cisco\|hp` | Cisco `show mac address-table`, HP `show mac-address`. Links hosts to their real VLAN. |
| `POST /ingest/arp?format_hint=cisco\|unix\|windows` | Cisco `show ip arp`, Linux/Unix and Windows `arp -a` |

Ingests that see IP↔MAC bindings go through host identity tracking. That covers DHCP renumbering,
IP conflicts (kept as separate hosts), and address history (`GET /hosts/{id}/history`).

### Baseline CSVs

Column names are matched case-insensitively, and common aliases are accepted. Each upload goes to
`?baseline_name=` (default `default`).

| Endpoint | Required columns | Optional |
|---|---|---|
| `POST /ingest/baseline/comms-matrix` (approved communications) | `src`, `dst`, `dst_port` | `protocol`, `service_name`, `conduit`, `owner` |
| `POST /ingest/baseline/approved-hosts` | `ip`, `role` (`jump_host`, `admin_ws`, `engineering_ws`, `hmi`) | `mac`, `hostname`, `zone`, `owner`, `notes` |
| `POST /ingest/baseline/asset-inventory` | `ip` or `mac` | `hostname`, `device_type`, `purdue_level`, `zone`, `vlan`, `sl_c`, `sl_c_source` (a row with `device_type` or `purdue_level` counts as a manual classification); other column names through a column mapping, below |
| `POST /ingest/baseline/reviewed-policies` | `policy_id` | `conduit`, `owner`, `notes`, `last_reviewed` |

**Asset inventory column mapping.** Inventory exports name their columns their own way
(`IP_Address`, `Host Name`, `Asset Type`). *Inventory → Import CSV…* reads the file without writing
anything (`POST /ingest/baseline/asset-inventory/preview`) and shows every column with sample values
and a suggested field: from the site's saved mapping, the field name itself, a known alias
(`ip address`, `mac address`, `host name`, `device type`, `asset type`, `purdue level`, `vlan id`,
`security zone` ...), the values (a column of addresses), or a guess from the header words - the last
two marked "check". The operator picks a field or *Ignore* per column. The checks run over every row:
no IP / MAC column, a field mapped from two columns, unknown fields or duplicate headers block the
import; rows without a usable IP / MAC, Purdue levels that are not 0-5 / 3.5 / dmz, SL-C values that
are not 1-4 and device type values the checks do not know are listed. A device type that names one
of the application's types in another case or spacing (`PLC`, `Engineering Workstation`) is stored as
that type; other values are stored as written. The import sends the mapping shown (`column_map`, JSON
`{"column": "field" or ""}`) and can save it per site (`save_mapping_as`). The next file whose
columns a saved mapping names (at least half of them) maps itself - in the preview and in plain
uploads that carry no mapping. An upload without a mapping (Upload page, curl) matches columns by
field name and alias only, never by a guess. Every import response names the mapping used
(`mapping_source`: `names`, `supplied` or `saved:<name>`; `columns_mapped`) and lists the columns it
left out (`columns_ignored`) and any problem (`mapping_problems`, e.g. no IP / MAC column); the
Upload page shows them. Saved mappings: `GET /ingest/baseline/asset-inventory/mappings`, `DELETE
/ingest/baseline/asset-inventory/mappings/{id}` (table `inventory_import_mappings`, migration
`8a9b0c1d2e3f`).

`dst_port` accepts a single port, an inclusive range `lo-hi` (stored as `dst_port` + `dst_port_end`),
a list `502,102` (one row per element), or `any`/blank. Anything else rejects the row; it is never
widened to `any`.

### MAC vendor lookup (OUI data)

`Host.vendor` comes from scapy's bundled `conf.manufdb` unless `IACS_MANUF_FILE` points at a
Wireshark-format `manuf` file. That is the same file Grassmarlin uses. On Wireshark 4+, generate one
with `tshark -G manuf > manuf`. Locally administered (randomised or virtual) MACs are flagged as
such and get no vendor.

---

## Findings and checks

Every finding carries an explanation ("Why this was flagged": a pop-up from the **?** button on each finding row or the finding panel, `GET /findings/{id}/explanation`): what was found (with the policy path and its NAT), why it is an issue, the 62443 requirement and workbook row, why it has its severity, how to resolve it, how it closes and how to verify it by hand. See docs/finding-explanations.md.

Every check writes to one `Finding` table. Each finding carries `check_name`, `category`,
`severity`, `status`, `isa62443_sr`, `checklist_id` (the row in the OT firewall review workbook),
`detail` (evidence JSON), `occurrence_count` and `last_seen`.

### Lifecycle

- **Dedup:** each finding has a `source_ref` hash of the check and its key evidence. While an
  **open or acknowledged** finding exists for that hash, a re-detection doesn't create a new row.
  It increments `occurrence_count`, updates `last_seen` and refreshes `detail`. A partial unique
  index (`ux_findings_source_ref_open`) allows at most one open finding per hash.
- **Escalation:** when a re-detection is more severe (for example, traffic now confirms a policy
  gap), the existing finding's severity, title and evidence are raised in place.
- **Acknowledged findings absorb recurrences.** A recurrence of an acknowledged finding doesn't
  spawn a new open duplicate. If the condition **escalates**, the finding is **re-opened** and a
  "Re-opened … severity escalated" note is added.
- **Recurrence after close:** a closed finding lets the same condition open a fresh finding.
- **Auto-resolve** (`IACS_AUTO_RESOLVE`, on by default): after a periodic review completes
  successfully and fully, its open findings that weren't reproduced are closed with an
  "Auto-resolved: …" note. A FortiGate re-ingest does the same for that firewall's `config_review`
  findings. Acknowledged and `real_time` findings are never auto-closed. Failed or incomplete
  (truncated-input) reviews never auto-resolve.
- **Manual transitions:** `PATCH /findings/{id}/status` moves a finding open → acknowledged →
  closed, with `notes` and `acknowledged_by`. Findings are kept as the audit trail. `DELETE` exists
  but is turned off by default.
- **False positives:** `status=false_positive` with a required `reason` (and `acknowledged_by` as
  the person) records that the operator judged the finding wrong. A false positive is never raised
  again as a new finding: a persisting condition updates it silently (`last_seen`,
  `occurrence_count`), an escalation only adds a note. It is left out of the findings in scope and
  listed in its own section, with the reason, at the end of the CSV export and in the PDF report
  ("False Positives"). Moving it back to open or closed keeps the reason in the notes.
- **Rule twins and `related_checks`:** one permissive rule can trip several rule-based checks.
  For example, IT→L1 Telnet trips `rule_cleartext_protocol`, `rule_mgmt_protocol`,
  `rule_cleartext_creds`, `rule_mgmt_wrong_zone` and `rule_it_ot_bypass`. These map to different checklist rows, so they
  stay as separate findings, one per **logical** rule (stable across re-ingests). Each one lists
  the others in `detail.related_checks`.
- **Failure isolation:** each real-time check and each periodic review runs in its own savepoint.
  A failing review is rolled back on its own and reported in `failed_reviews`.
  `GET /diagnostics` shows the last run's failures, escalations and auto-resolves, plus any
  unregistered `check_name`s.

### When checks run

| Category | Trigger |
|---|---|
| `real_time` | Each new log event (`/ingest/forti-*`, `/ingest/syslog`) |
| `periodic_review` | `POST /reviews/run` or the scheduler. Runs 36 review functions over sessions, rules, hosts, switch/VLAN data, baselines and attestations. Also used by the checklist 8.4 traffic check on PCAP ingest and `POST /findings/scan-industrial-writes`. |
| `config_review` | FortiGate config ingest (inline `config_*` checks and `fqdn_in_policy`), and the cross-firewall checks (`POST /topology/run-checks` and after `confirm-link`) |

### Foundational requirements and security levels (`app/security_levels.py`)

Each check and finding gets two values, derived from its SR text:

- **`fr`**: the ISA/IEC 62443-3-3 foundational requirements its SRs belong to (SR 5.x → FR5,
  Restricted data flow).
- **`security_level`**: the lowest security level at which one of its SRs or requirement
  enhancements applies, from the SL-C table in 62443-3-3 Annex B. For example `SR 5.1 RE2`
  gives 3, and `SR 5.1 RE2, SR 5.2` gives 1.

They are computed from each finding's own SR text, so the inline `config_*` checks get them
too. A finding with no 62443-3-3 SR has no FR and no level. That covers the 62443-2-1-only
items: `zone_doc_1_6`, `config_rules_missing_owner` and `remote_access_app`. These apply at
every level, so a target-level filter always keeps them; an FR filter leaves them out.

Where the filters are:

- **Findings page:** *Target SL* and *FR* filters, an SL badge on each row, and *Foundational
  requirement* / *Security level* group-by options.
- **Reports page:** a *Target security level* option for the PDF.
- **API:** `?target_sl=` and `?fr=` on `/findings`, `/findings/summary` and
  `/findings/export`.

Check the table in `app/security_levels.py` against your licensed copy of the standard.

### Check reference (`CHECK_TYPE_REFERENCE`, app/models.py)

This table is generated from `app.models.CHECK_TYPE_REFERENCE` (185 entries, regenerated 2026-10-19). Each entry is
check_name → (SR references, checklist row, default severity, category). Checks can raise severity
from context, for example when matching traffic is observed.

| Check | Category | ISA/IEC 62443 SR | Checklist | Default severity |
|---|---|---|---|---|
| `config_av_missing_on_file_policy` | config_review | SR 3.3, SR 3.2 | - | medium |
| `fqdn_in_policy` | config_review | SR 7.6 | - | medium |
| `zone_doc_1_1` | periodic_review | SR 5.1 | 1.1 | high |
| `host_in_multiple_zones` | periodic_review | SR 5.1 | 1.2 | medium |
| `network_in_multiple_zones` | periodic_review | SR 5.1 | 1.2 | medium |
| `zone_doc_1_2` | periodic_review | SR 5.1 | 1.2 | high |
| `flat_control_segment` | periodic_review | SR 5.1 | 1.2, 1.3 | low |
| `paired_firewall_vendor_diversity` | periodic_review | SR 5.1, SR 5.2 | 1.3 | low |
| `zone_doc_1_3` | periodic_review | SR 5.1 RE1, SR 5.2 | 1.3 | high |
| `conduit_service_blocked` | periodic_review | SR 5.1 | 1.4 | info |
| `undocumented_conduit` | periodic_review | SR 5.1 | 1.4 | medium |
| `zone_doc_1_4` | periodic_review | SR 5.2, ZCR 3 | 1.4 | medium |
| `zone_doc_1_5` | periodic_review | SR 5.1, SR 1.1 | 1.5 | medium |
| `zone_doc_1_6` | periodic_review | 2-1 SPE 2 | 1.6 | medium |
| `access_path_enumeration_truncated` | periodic_review | SR 7.1 | 2.1, 2.2 | info |
| `chain_it_ot_bypass` | periodic_review | SR 5.1 RE2, SR 5.2 | 2.1, 2.2 | high |
| `chain_ot_upward_skip` | periodic_review | SR 5.1 RE2, SR 5.2 | 2.1, 2.2 | medium |
| `intervlan_routing_unchecked` | periodic_review | SR 5.1 RE2, SR 5.2 | 2.1, 2.2 | critical |
| `it_ot_bypass` | real_time | SR 5.1 RE2, SR 5.2 | 2.1, 2.2 | critical |
| `rule_it_ot_bypass` | periodic_review | SR 5.1 RE2, SR 5.2 | 2.1, 2.2 | high |
| `session_it_ot_bypass` | periodic_review | SR 5.1 RE2, SR 5.2 | 2.1, 2.2 | critical |
| `switch_dual_gateway` | periodic_review | SR 5.2 | 2.1, 2.2 | high |
| `switch_routes_between_zones` | periodic_review | SR 5.1 RE2, SR 5.2 | 2.1, 2.2 | high |
| `dmz_bypass` | periodic_review | SR 5.1 RE2, SR 5.2 | 2.2 | medium |
| `historian_in_control_zone` | periodic_review | SR 5.1, SR 7.8 | 2.3 | high |
| `config_no_internal_segmentation` | config_review | SR 5.1 | 2.4 | medium |
| `sis_zone_not_isolated` | periodic_review | SR 5.1, SR 5.2, 2-1 NET 1.3 | 2.4 | high |
| `switch_acl_wrong_direction` | periodic_review | SR 5.2 | 2.4 | medium |
| `config_wireless_not_isolated` | config_review | SR 1.6 | 2.5 | high |
| `config_wireless_weak_security` | config_review | SR 1.6, SR 4.1 | 2.5 | medium |
| `mgmt_access_not_restricted` | periodic_review | SR 1.3, SR 5.1 | 2.5 | medium |
| `config_possible_dual_homed` | config_review | SR 5.1 | 2.6 | high |
| `multi_homed_host` | periodic_review | SR 5.1 | 2.6 | high |
| `wireless_in_ot_zone` | periodic_review | SR 7.7 | 2.6 | high |
| `misplaced_device` | periodic_review | SR 5.1, SR 7.8 | 2.7 | high |
| `vlan_zone_mismatch` | periodic_review | SR 5.1 RE2, SR 5.2 | 2.7 | high |
| `config_policy_any_interface` | config_review | SR 5.2, SR 5.1 | 3.1 | medium |
| `denied_trend` | periodic_review | SR 5.2 RE1 | 3.1 | info |
| `policy_spans_multiple_conduits` | periodic_review | SR 5.1, SR 5.2 | 3.1 | low |
| `rule_implicit_permit` | periodic_review | SR 5.2, SR 5.1 | 3.1 | medium |
| `config_temporary_rule` | config_review | 2-1 SPE 2 | 3.11 | medium |
| `config_vendor_rule_permanent` | config_review | SR 1.13, 2-1 NET 3.2 | 3.11 | low |
| `config_ids_ips_missing` | config_review | SR 3.3, SR 6.2 | 3.12 | medium |
| `config_industrial_dpi_missing` | config_review | SR 5.2, SR 3.5 | 3.12 | medium |
| `ips_ot_conduit` | real_time | SR 5.2, SR 3.5 | 3.12 | high |
| `config_rsp_check_disabled` | config_review | SR 5.2 | 3.13 | medium |
| `config_permit_any_any_any` | config_review | SR 5.2, SR 7.7 | 3.2 | critical |
| `access_path_permissive` | periodic_review | SR 5.2, SR 7.7, SR 4.1 | 3.2, 3.5 | medium |
| `config_overly_broad_subnet` | config_review | SR 5.2 | 3.3 | low |
| `config_service_protocol_mismatch` | config_review | SR 5.2 | 3.3 | low |
| `config_same_zone_rule` | config_review | SR 5.2 | 3.4 | low |
| `cleartext_protocol` | periodic_review | SR 7.7, SR 4.1 | 3.5 | medium |
| `config_icmp_across_boundary` | config_review | SR 5.2, SR 7.7 | 3.5 | info |
| `rule_cleartext_protocol` | periodic_review | SR 7.7, SR 4.1 | 3.5 | medium |
| `smbv1_legacy` | periodic_review | SR 7.7, SR 4.1 | 3.5 | high |
| `weak_tls_observed` | periodic_review | SR 4.3, SR 4.1 | 3.5 | medium |
| `config_email_web_to_ot` | config_review | SR 5.3 | 3.6 | medium |
| `dead_default_gateway` | periodic_review | SR 7.6, SR 5.1 | 3.7 | medium |
| `path_ot_internet_egress` | periodic_review | SR 5.1 RE2 | 3.7 | high |
| `ot_internet_egress` | real_time | SR 5.1 RE2 | 3.7, 9.11, 9.12 | high |
| `session_ot_internet_egress` | periodic_review | SR 5.1 RE2 | 3.7, 9.11, 9.12 | high |
| `config_vip_unused` | config_review | SR 7.7, SR 5.2 | 3.8 | medium |
| `dead_end_permit` | periodic_review | SR 7.7, SR 5.2 | 3.8 | low |
| `disabled_rule` | periodic_review | SR 7.7 | 3.8 | low |
| `unused_policy` | periodic_review | SR 7.7 | 3.8 | low |
| `shadow_rule` | periodic_review | SR 7.6 | 3.9 | medium |
| `config_vpn_destination_unclear` | config_review | SR 1.13 | 4.1 | medium |
| `config_vpn_direct_to_ot` | config_review | SR 1.13 | 4.1 | critical |
| `config_vpn_no_routing_policy` | config_review | SR 1.13 | 4.1 | medium |
| `remote_access_bypass` | real_time | SR 1.13 | 4.1 | critical |
| `session_remote_access_bypass` | periodic_review | SR 1.13 | 4.1 | critical |
| `vpn_direct_to_ot` | periodic_review | SR 1.13, SR 5.2, SR 5.1 | 4.1, 2.1 | critical |
| `config_ipsec_dialup_psk` | config_review | SR 1.2, SR 1.1 | 4.2 | low |
| `config_ipsec_peer_unrestricted` | config_review | SR 1.2, SR 1.9 | 4.2 | medium |
| `config_sslvpn_weak_tls` | config_review | SR 4.1, SR 4.3 | 4.2 | medium |
| `config_weak_ipsec_crypto` | config_review | SR 4.3, SR 4.1, SR 3.1 | 4.2 | medium |
| `config_vpn_shared_access` | config_review | SR 2.8, SR 1.1 | 4.3 | low |
| `config_vpn_source_unrestricted` | config_review | SR 1.13 RE1 | 4.3 | high |
| `config_vpn_user_no_mfa` | config_review | SR 1.7, SR 1.13 RE1 | 4.3 | high |
| `config_vpn_idle_timeout_long` | config_review | SR 2.6 | 4.4 | low |
| `config_vpn_no_idle_timeout` | config_review | SR 2.6 | 4.4 | medium |
| `remote_access_app` | real_time | 2-1 NET 3.1 | 4.5 | high |
| `session_remote_access_app` | periodic_review | 2-1 NET 3.1, SR 1.13 | 4.5 | high |
| `config_remote_session_not_logged` | config_review | SR 2.8 | 4.6 | medium |
| `chain_mgmt_wrong_zone` | periodic_review | SR 1.3, SR 5.1 RE1 | 5.1 | medium |
| `config_mgmt_not_restricted_to_mgmt_zone` | config_review | SR 5.1 | 5.1 | medium |
| `cross_fw_any_any_permit` | config_review | SR 5.1 RE1 | 5.1 | critical |
| `cross_fw_missing_deny_all` | config_review | SR 5.1 RE1 | 5.1 | high |
| `cross_fw_no_rules` | config_review | SR 5.1 | 5.1 | high |
| `mgmt_access_from_wrong_zone` | periodic_review | SR 1.3, SR 5.1 RE1 | 5.1 | medium |
| `rule_mgmt_wrong_zone` | periodic_review | SR 1.3, SR 5.1 RE1 | 5.1 | medium |
| `switch_mgmt_svi_unrestricted` | periodic_review | SR 5.1 RE1, SR 1.3 | 5.1 | medium |
| `mgmt_protocol` | periodic_review | SR 1.3, SR 5.1 RE1, SR 4.1 | 5.1, 5.2 | medium |
| `rule_mgmt_protocol` | periodic_review | SR 1.3, SR 5.1 RE1, SR 4.1 | 5.1, 5.2 | medium |
| `config_insecure_mgmt_protocol` | config_review | SR 4.1, SR 3.1 | 5.2 | high |
| `config_snmp_v1v2c_enabled` | config_review | SR 4.1, SR 1.5 | 5.2 | medium |
| `cross_fw_asymmetric_permit` | config_review | SR 5.2 | 5.2 | medium |
| `switch_insecure_mgmt_protocol` | config_review | SR 4.1, SR 3.1 | 5.2 | high |
| `switch_snmp_cleartext_community` | config_review | SR 4.1, SR 1.5 | 5.2 | low |
| `config_no_password_policy` | config_review | SR 1.5, SR 1.7 | 5.4 | high |
| `config_snmp_default_community` | config_review | SR 1.5, SR 4.1 | 5.4 | high |
| `config_weak_password_policy` | config_review | SR 1.5, SR 1.7 | 5.4 | medium |
| `default_credentials_observed` | periodic_review | SR 1.5, SR 4.1 | 5.4 | high |
| `switch_snmp_default_community` | config_review | SR 1.5, SR 4.1 | 5.4 | high |
| `config_admin_idle_timeout_long` | config_review | SR 1.11, SR 1.12 | 5.5 | low |
| `config_admin_lockout_threshold_high` | config_review | SR 1.11, SR 1.12 | 5.5 | medium |
| `config_no_admin_idle_timeout` | config_review | SR 1.11, SR 1.12 | 5.5 | medium |
| `config_no_admin_lockout` | config_review | SR 1.11, SR 1.12 | 5.5 | high |
| `config_no_login_banner` | config_review | SR 1.12 | 5.5 | low |
| `auth_failure` | real_time | SR 1.11, SR 1.12, SR 2.1 | 5.5, 9.5 | high |
| `session_mgmt_from_non_admin` | periodic_review | SR 1.11, SR 1.12, SR 2.1 | 5.5, 9.5 | high |
| `config_unused_interface_not_disabled` | config_review | SR 7.7 | 5.7 | low |
| `config_admin_no_trusted_hosts` | config_review | SR 5.1, SR 2.1 | 5.8 | high |
| `config_local_in_permits_all` | config_review | SR 5.1, SR 2.1 | 5.8 | medium |
| `config_implicit_deny_not_logged` | config_review | SR 2.8, SR 6.2 | 6.1 | medium |
| `config_logging_disabled` | config_review | SR 2.8 | 6.1 | high |
| `nat_hides_source_into_ot` | periodic_review | SR 2.8, SR 6.2 | 6.1 | medium |
| `config_monitoring_readiness` | config_review | SR 2.8, SR 6.1, SR 6.2 | 6.1, 6.2 | medium |
| `fw_config_change` | real_time | SR 2.8, SR 2.12 | 6.2 | high |
| `config_no_syslog_forwarding` | config_review | SR 6.1, SR 6.2, SR 2.9 | 6.3 | high |
| `log_silence` | real_time | SR 6.1, SR 2.9 | 6.3 | high |
| `config_ntp_fortiguard` | config_review | SR 2.11 | 6.4 | info |
| `config_ntp_unauthenticated` | config_review | SR 2.11, SR 3.1 | 6.4 | low |
| `config_fail_open_enabled` | config_review | SR 5.2 RE3 | 7.1 | critical |
| `config_no_dos_policy_ot` | config_review | SR 7.1, SR 7.2 | 7.1 | low |
| `single_path_critical_device` | periodic_review | SR 7.7, SR 7.1 | 7.1 | medium |
| `no_path_redundancy_verified` | periodic_review | SR 7.1, SR 7.2 | 7.2 | low |
| `ot_it_dependency` | periodic_review | SR 5.1 RE2, SR 1.1 | 7.3, 9.2 | low |
| `rule_ot_it_dependency` | periodic_review | SR 5.1 RE2, SR 1.1 | 7.3, 9.2 | low |
| `config_ha_no_monitor_interfaces` | config_review | SR 7.1, SR 7.2 | 7.4 | low |
| `ha_config_drift` | periodic_review | SR 7.6, SR 7.2 | 7.4 | medium |
| `ha_failover` | real_time | SR 7.1, SR 7.2 | 7.4 | low |
| `ha_system_error` | real_time | SR 7.1, SR 7.2 | 7.4 | medium |
| `config_no_revision_backup` | config_review | SR 7.3, SR 7.6 | 7.5 | low |
| `config_no_scheduled_backup` | config_review | SR 7.3, SR 7.2 | 7.5 | low |
| `config_device_detection_disabled` | config_review | SR 7.8 | 7.7 | info |
| `undocumented_lldp_device` | periodic_review | SR 7.8 | 7.7 | medium |
| `firmware_not_documented` | periodic_review | SR 7.8, SR 2.2 | 7.8 | low |
| `conduit_matrix_drift` | periodic_review | SR 5.2, ZCR 3 | 8.1, 8.2 | medium |
| `rule_conduit_drift` | periodic_review | SR 5.2, ZCR 3 | 8.1, 8.2 | medium |
| `session_no_permitting_rule` | periodic_review | SR 5.2 | 8.1, 8.2 | medium |
| `config_av_profile_not_applied` | config_review | SR 3.2 | 8.10 | low |
| `config_no_av_profile` | config_review | SR 3.2 | 8.10 | medium |
| `cleartext_credentials` | periodic_review | SR 4.1, SR 3.1 | 8.3 | high |
| `rule_cleartext_creds` | periodic_review | SR 4.1, SR 3.1 | 8.3 | high |
| `engineering_access_unapproved` | periodic_review | SR 2.1, SR 1.3 | 8.4 | medium |
| `unauth_ot_write` | real_time | SR 2.1, SR 3.5 | 8.4 | critical |
| `unauthorized_industrial_write` | periodic_review | SR 2.1, SR 3.5 | 8.4 | critical |
| `config_broadcast_cross_zone` | config_review | SR 5.1, SR 7.7 | 8.5 | medium |
| `ghost_vlan` | periodic_review | SR 6.2 | 8.6 | high |
| `rogue_dhcp_server` | periodic_review | SR 7.6, SR 5.1 | 8.6 | high |
| `transient_device_in_ot_zone` | periodic_review | SR 7.8, SR 5.1, 2-1 NET 1.1 | 8.6 | medium |
| `unknown_device` | periodic_review | SR 7.8 | 8.6 | medium |
| `ip_conflict` | periodic_review | SR 7.8 | 8.7 | high |
| `blocked_cross_zone_attempts` | periodic_review | SR 5.1, SR 6.2 | 8.8 | low |
| `scanning_denied` | real_time | SR 6.2, SR 7.1 | 8.8 | medium |
| `session_scanning_anomaly` | periodic_review | SR 6.2, SR 7.1 | 8.8 | medium |
| `config_split_tunneling_enabled` | config_review | SR 1.13, SR 5.1 | 9.1 | medium |
| `config_syslog_unencrypted` | config_review | SR 6.1, SR 2.9 | 9.10 | medium |
| `config_dns_external` | config_review | SR 5.1 RE2, SR 7.6 | 9.11 | medium |
| `rule_dns_external` | periodic_review | SR 5.1 RE2, SR 7.6 | 9.11 | medium |
| `config_updates_from_internet` | config_review | SR 5.1 RE2, SR 3.4 | 9.12 | medium |
| `config_auto_firmware_upgrade` | config_review | SR 7.6, 2-1 SPE 2 | 9.12 | low |
| `config_link_monitor_external` | config_review | SR 7.1, SR 7.6 | 7.4 | info |
| `config_wireless_in_ot` | config_review | SR 1.6, SR 5.1 | 2.5 | high |
| `switch_port_no_nac` | periodic_review | SR 1.2, SR 2.1 | 2.4 | low |
| `switch_unused_port_enabled` | periodic_review | SR 7.7 | 5.7 | low |
| `config_default_hostname` | config_review | SR 2.11 | 9.13 | low |
| `config_no_timezone` | config_review | SR 2.11 | 9.13 | low |
| `config_rules_missing_owner` | config_review | 2-1 SPE 2 (CM) | 9.14 | low |
| `ntp_sync` | periodic_review | SR 7.6, 2-1 NET 1.4 | 9.3 | medium |
| `config_admin_no_two_factor` | config_review | SR 1.7, SR 1.1 RE1 | 9.4 | medium |
| `config_fortimanager_admin_access` | config_review | SR 1.1, SR 1.13 | 9.4 | info |
| `config_admin_profile_overprivileged` | config_review | SR 2.1, SR 1.3 | 9.4 | medium |
| `config_no_central_auth` | config_review | SR 1.1, SR 1.3 | 9.4 | medium |
| `auth_from_non_admin_host` | real_time | SR 2.1 | 9.5 | high |
| `config_admin_trusthost_outside_mgmt` | config_review | SR 5.1, SR 2.1 | 9.5 | medium |
| `config_admin_trusthost_too_broad` | config_review | SR 5.1, SR 2.1 | 9.5 | medium |
| `config_usb_auto_install_config` | config_review | SR 2.3, SR 3.4 | 9.6 | high |
| `config_usb_auto_install_image` | config_review | SR 2.3, SR 3.4 | 9.6 | high |
| `config_maintainer_account_enabled` | config_review | SR 2.1 | 9.7 | high |
| `config_maintainer_named_account` | config_review | SR 2.1 | 9.7 | medium |
| `config_strong_crypto_disabled` | config_review | SR 4.3, SR 4.1 | 9.8 | medium |
| `config_weak_tls_version` | config_review | SR 4.1 | 9.8 | high |
| `config_ha_no_auth` | config_review | SR 3.1 | 9.9 | medium |

Notes on the table:

- `zone_doc_1_1` … `zone_doc_1_6` open only when no current, non-stale **attestation** exists for
  that checklist row. Attestations are submitted through `POST /attestation` or the console.
- The `session_*` checks are NetworkSession-based fallbacks for the real-time checks. They're
  skipped while FortiAnalyzer data is present.

**Checks outside that table.** These write SR and checklist metadata inline. `GET
/findings/category-reference` returns the 55 entries above plus these 6:

| Check | Category reported by `/findings/category-reference` | SR | Checklist | Severity |
|---|---|---|---|---|
| `cross_fw_no_rules` | config_review | SR 5.1 | 5.1 | high |
| `cross_fw_missing_deny_all` | config_review | SR 5.1 RE1 | 5.1 | high |
| `cross_fw_any_any_permit` | config_review | SR 5.1 RE1 | 5.1 | critical |
| `cross_fw_asymmetric_permit` | config_review | SR 5.2 | 5.2 | medium |
| `cross_fw_same_permit_both_sides` | config_review | SR 5.2 | 5.2 | info |
| `unauthorized_industrial_write` | traffic_review (stored with `category=periodic_review`) | SR 2.1, SR 3.5 | 8.4 | critical |

The FortiGate config parser also emits inline `config_*` checks, such as
`config_logging_disabled`, `config_permit_any_any_any` ('all' in source, destination or service), `config_temporary_rule` (row 3.11), `config_vpn_direct_to_ot`,
`config_ntp_fortiguard`, `config_no_admin_lockout` and `config_monitoring_readiness` (what the firewall does
not log or send, across every log destination). Their metadata is attached per finding. List
them with `GET /findings?category=config_review`.

---

## Sites (multi-site)

A **site** is one plant / facility. Sites are kept apart: every upload names its site, every root
record (firewalls, firewall devices, rules, NAT rules, zones, hosts, PCAP captures, log events,
findings, baselines, attestations, switch ports, VLANs, MAC table entries) carries `site_id`, and
every list endpoint can be filtered to one site. Design and roadmap:
[`docs/multi-site-design.md`](docs/multi-site-design.md). All four phases are implemented:
1. sites table, `site_id` on root rows, Default backfill, required `site` on uploads, list filters,
   console site selector;
2. site-scoped identity and per-site analysis, reviews, baselines, attestations and reports;
3. device registry, per-line log routing, unmapped queue with mapping and replay, Devices page;
4. retention, the read-only cross-site roll-up (`GET /sites/rollup`, console **Sites overview**),
   per-site and all-sites PDF reports, this documentation.

- **No site on a fresh install (FI-01).** A new database has no site; the operator creates the
  first one (console **+ New site**, or `POST /sites`). Nothing creates a site implicitly: listing
  sites, the scheduler and the review run do not, and a per-site operation with no site at all
  answers **409** ("No site exists yet"). The site *Default* (code `default`) exists only on a
  database upgraded from before sites (migration `c0d1e2f3a4b5` assigns the existing rows to it)
  or when a request names `site=default` explicitly.
- **`site` is required on every non-log upload**: `/ingest/pcap`, `/ingest/pcap-fw`, `/ingest/arp`,
  `/ingest/firewall`, `/ingest/fortigate-config`, `/ingest/switch`, `/ingest/mac-table`,
  `/ingest/baseline/*` (query parameter) and `POST /attestation` (form field). The value is a site
  **id, name or code** (names and codes are case-insensitive). Missing or unknown → **422** with a
  message naming the known sites. Responses echo `site_id` and `site` (name).
- **Log uploads** (`/ingest/syslog`, `/ingest/forti-syslog`, `/ingest/forti-event`,
  `/ingest/forti-report`) are **routed per line** to the site of the device that sent it, looked
  up in the device registry (`site_devices`) by **serial** first (FortiGate `devid` / CEF
  `deviceExternalId`, PAN-OS serial), then by **device name** (FortiGate `devname`, syslog
  hostname of ASA / pfSense, PAN-OS device name; case-insensitive). The event is stored in that
  site and the real-time checks run there.
  - **Unknown devices**: their lines are **held** in `unmapped_log_events` - no event, no checks,
    re-uploads deduplicated - until the device is mapped. A name registered at two sites (allowed
    only with distinct serials) is ambiguous for a line without a known serial and is held too.
  - **`?site=`** (optional) maps the *unknown* devices of that upload to the site (registered with
    `source: manual`) and routes their lines there. It never overrides an existing mapping and
    never guesses: lines of devices registered to **another** site are held as `site_mismatch`
    conflicts (counted in `site_conflicts`, see below). Lines without any device identity go to
    `?site`, else they are held (never the Default site).
  - **Conflicts (B-11)** - a conflicting line is never routed by guess; it is held until you
    decide (no event, no checks):
    - *Serial binding*: when a name-matched device has **no** serial registered and its line
      carries one, that serial is recorded on the device (`serial_source: first_seen`,
      `serial_bound_at`) and the line routes normally.
    - *`serial_conflict`*: the line's serial differs from the serial registered for its device
      name (and is registered nowhere) → held. A serial registered to **another** device always
      routes to that device (serial wins).
    - *`site_mismatch`*: a `?site=` upload carries lines of a device registered to another site →
      held. Without `?site=`, name-only devices (ASA, pfSense) with a unique name keep routing by
      name.
    - Resolve per group (device, kind, line serial) with `POST /site-devices/conflicts/resolve`
      or the console's **Conflicts** list: `same_device` (a replaced unit: the registered serial
      becomes the line's serial, `serial_source: conflict_resolution`; held lines are replayed
      into the registered site), `different_device` + `site` (+ `device_name`) (a new device with
      the line's serial is registered at that site and the lines are replayed there; future lines
      route there by serial), `add_ha_member` (B-12, below) or `discard` (needs
      `IACS_ENABLE_DELETE=true`). For a `site_mismatch` the lines carry the registered device's
      identity, so `different_device` is refused (409): if the device really moved, remap it
      (`PATCH /site-devices/{id}`) and choose `same_device`. Replays use the normal ingest path,
      so the real-time checks run in the chosen site; stored data is never moved. Every
      resolution is recorded (`GET /site-devices/conflicts/resolutions`).
    - Held lines are deduplicated per resolved device key (including the `?device_name`
      fallback) **and** serial, so one identity-less line uploaded for fwA and then for fwB is
      held once per device.
  - **HA clusters (B-12)** - an FGCP cluster is **one** registered device with one serial per
    member unit (`site_device_serials`, each serial globally unique; at most
    `IACS_HA_MAX_MEMBERS`, default 4 = the FGCP limit). Lines carrying **any** member serial route
    to the device's site.
    - A FortiGate config upload with `config system ha` marks its device HA per site and hostname
      (`set mode a-p` / `a-a`, `group-name`, `group-id` → `is_ha`, `ha_mode`, `ha_group_name`,
      `ha_group_id`); `mode standalone` (or no `mode`) clears it; a config without the block
      leaves it unchanged.
    - The first serial seen still binds (B-11). A further serial under an HA device's name is
      **added automatically** (`source: ha_evidence`, audited as action `ha_evidence`) when an HA
      event log from a known member names it as a peer - FortiOS `logid` 0108037894 *member joined*
      or 0108037892 *member state moved*, field `sn`, with `ha_group` matching `group-id` when both
      are known - or when it was pre-registered (`POST /site-devices/{id}/serials`). Otherwise
      its lines are held as **`ha_candidate`** conflicts; the console offers **Add as HA member**
      first (`action: add_ha_member`; for a device not marked HA it needs `mark_ha: true`).
      Evidence arriving later (same file or a later upload) replays the held candidates.
      Never across sites (a held line whose upload named another site stays held), never beyond
      the maximum; a standalone device is unchanged (B-11 `serial_conflict`).
    - **HA failover finding**: for an **a-p** cluster, a change of the active member (forwarded
      traffic now logged by the other serial, or a *member state moved* log naming a new
      `ha_role=master`) raises `ha_failover` (low, real_time, SR 7.1/7.2, checklist 7.4, one per
      device / new primary / hour; never auto-closed, like other real-time findings). Active-active
      clusters and unknown modes never raise it. Each member shows `last_seen_at` / `last_role`.
  - The response carries `routing`: `routed` (per site: events created / duplicates), `unmapped`,
    `unmapped_duplicates`, `conflicts`, `conflict_duplicates`, `serial_conflicts`,
    `site_conflicts`, `ha_candidates`, `ha_members` (members added on HA evidence, with their
    replay), `serial_bindings`, `new_mappings`, `mapped_devices`, `replayed`; the stats
    also count `conflicts` (lines held for a decision) next to `unmapped`.
- **Device registry.** Firewall config uploads (`/ingest/fortigate-config`, `/ingest/firewall`)
  register the config's hostname (else the explicit firewall name) for the upload's site (`source:
  config_upload`); a device already registered to a **different** site is not moved - the upload
  response lists it in `site_device_conflicts`. Mapping a device (`POST /site-devices`, also on
  config registration and `?site=`) **replays** its held lines into the site; remapping
  (`PATCH`) affects **new lines only** - stored events and findings stay where they are (held
  lines still pending are replayed into the new site).
- **Retention.** Held lines that were replayed or discarded, and pending ones older than
  `IACS_UNMAPPED_RETENTION_DAYS` (default 30), are purged daily by the scheduler and on
  `POST /site-devices/unmapped/purge` (`days` overrides the period; an invalid env value falls back
  to 30). Only held lines are purged: findings, events and other stored data are never deleted
  automatically.
- **Roll-up** (`GET /sites/rollup`, read-only). Per site: firewalls, firewall devices, hosts, open
  findings by severity (`open_critical` / `open_high` called out), `last_review_at` (last periodic
  review run for the site **in this server process**, null after a restart), `last_upload_at`
  (newest firewall config / PCAP upload), `baseline_active` (name or null) and `attestation`
  (`state` `current` when all six 1.1-1.6 rows are current and under 365 days old, else `overdue`,
  with `current` / `stale` / `missing` counts). Plus `totals`, `unmapped_pending` and
  `conflicts_pending` (global).
  It only aggregates, using one grouped query per metric; no analysis runs and nothing is written.
  The console's **Sites overview** page shows it as one card per site; *Open findings* selects the
  site and opens Findings, *PDF report* downloads that site's report.
- **Report layouts (2026-10-18).** `layout=lrqa` (default; CLI `--layout`) is the **LRQA compliance report**, which follows the owner's technical-report template: a cover with the
  navy panel, the IACS Monitor wordmark and the Prepared For / Project / Author / Date block; a Contents
  page with real page numbers; 1 Distribution List and 2 Revision History (from the Reports page's *Report
  details*); 3 Engagement Particulars (background, scope - firewalls, networks, inputs, target SL -,
  assessment window / constraints, the finding summary by severity as checks / occurrences, then the
  executive detail: coverage, severity and per-area tables, remediation priorities); 4 Findings (one row
  per check: title, severity, reference, analysis section); 5 Analysis (per check: a key-value box,
  Description of the Issue, Configuration / Observed Values - the evidence of the findings instead of
  figures -, Affected Components, IACS_Monitor Recommends, FortiOS Example, Further Reading); 6 Appendix
  (severity methodology, then the former sections: false positives, closed findings, excluded checks,
  attestations, zones and conduits, firewall inventory, shadowed rules, access review, check coverage,
  configuration evidence, control mapping, standards). `layout=public` is the **public compliance report**: the
  previous layout (cover table, executive summary, findings by area with the write-ups, the supporting sections).
  The Reports page has the choice under *Report layout*.
- **Findings in the PDF (2026-10-17).** One write-up per check - concern, why it is a finding,
  remediation, a FortiOS example filled from the finding for FortiGate configuration checks
  (`app/writeup.py`), when it closes - with the standard / best-practice references (IEC 62443-3-3
  SR and title, IEC 62443-2-1 / 3-2, NIST SP 800-82r3 + SP 800-53 controls, CIS FortiGate Benchmark
  topic) in place of the checklist number, SR, FR and SL; then one table of every affected firewall /
  device of the site (policies, interfaces / VLANs / subnets, hosts, highest severity, status counts)
  instead of one row per finding. The FR x SL matrix is not printed any more.
- **Per-site PDF.** `GET /reports/compliance.pdf?site=<id|name|code>` (or `site_id=`) is a
  single-site report: the cover names the site (name and code) and every section holds only that
  site's data (the site is required when several exist). `all_sites=true` produces the roll-up:
  a summary table, then one complete section per site, and the control mapping once.
- **Derived rows follow their parent**: a rule takes its firewall's site, a finding the site of its
  rule, session (source host) or log event. Rows created by analyses with no such parent (periodic
  reviews, cross-firewall checks) land in the site the analysis runs in.
- **Filters.** `site_id=<id>` on `/findings`, `/findings/summary` (which also returns `by_site`
  open counts), `/findings/export`, `/findings/export/summary`, `/hosts`, `/assets`,
  `/assets/export`, `/sessions` (site of the source host), `/firewall-rules`, `/firewall-devices`,
  `/firewall-zones`, `/nat-rules`, `/switch-interfaces`, `/topology`, `/topology/state`,
  `/topology/firewalls`, `/attestation`, `/baselines` and `/reports/compliance.pdf`. Omit it for
  all sites; an unknown id is a 422. List rows include `site_id` (and `site_name` where cheap).
  (`/assets?site=` is unrelated: it filters the free-text *location* field of the inventory.)
- **Isolation** (phase 2): identities are per site (the same IP / MAC / firewall name / baseline
  name at two sites are independent rows) and every analysis - reviews, reachability, shadowing,
  cross-FW, `/diff`, classification, real-time checks - runs inside one site
  (`app/parsers/site_scope.py`).

| Method | Path | Body / params | Purpose |
|---|---|---|---|
| GET | `/sites` | | All sites with `counts` (`firewalls`, `firewall_devices`, `hosts`, `open_findings`, `devices` = registered log devices, `unmapped_pending` = held lines of unmapped devices and `conflicts_pending` = held conflict lines, both global) |
| POST | `/sites` | JSON `{"name", "code"?, "description"?}` | Create (201). `code` defaults to a slug of the name. Duplicate name/code (any case) → 409 |
| GET | `/sites/{id}` | | One site with counts |
| PATCH | `/sites/{id}` | JSON, any of `name`, `code`, `description` | Rename / recode; data stays attached by id |
| DELETE | `/sites/{id}` | `force` | Needs `IACS_ENABLE_DELETE=true`. 409 for the last site, and while the site has data unless `force=true` (then all of its data is deleted with it) |
| GET | `/site-devices` | `site_id` | Registered log devices (`device_name`, `serial` / `serial_source` / `serial_bound_at` = first member, `members` [`serial`, `source`, `added_at`, `last_seen_at`, `last_role`], `is_ha`, `ha_mode`, `ha_group_name`, `ha_group_id`, `max_members`, `vendor`, `site`, `source`) |
| POST | `/site-devices` | JSON `{"site", "device_name"?, "serial"?, "vendor"?}` | Map a device (201; 200 if already mapped there) and replay its held lines (`replay` counts). 409 when registered to another site |
| PATCH | `/site-devices/{id}` | JSON, any of `site`, `device_name`, `serial`, `vendor` | Edit / remap (new lines only; an HA cluster moves with all its members); replays still-pending held lines. `serial` replaces the only serial (409 for a cluster with several members) |
| POST | `/site-devices/{id}/serials` | JSON `{"serial"}` | B-12: pre-register a member serial (201; 200 if already a member) and replay lines held for it. 409 when registered to another device (any site), when the device is standalone and has a serial, or when the cluster is full |
| DELETE | `/site-devices/{id}/serials/{serial}` | | Needs `IACS_ENABLE_DELETE=true`. Remove a member serial; new lines with it are held again |
| DELETE | `/site-devices/{id}` | | Needs `IACS_ENABLE_DELETE=true`. Unregister; new lines from it are held again |
| GET | `/site-devices/unmapped` | `detail`, `status` (pending), `device_key`, `limit` | Held lines grouped by device: count, first/last seen, vendor, serial, sample line; `pending_lines` total |
| POST | `/site-devices/unmapped/discard` | JSON `{"device_key"}` | Discard a device's pending held lines |
| POST | `/site-devices/unmapped/purge` | `days` | Retention purge now |
| GET | `/site-devices/conflicts` | `detail`, `site_id` (registered or requested site), `kind` (`serial_conflict` / `site_mismatch` / `ha_candidate`), `limit` | Held conflicts grouped by device key + kind + line serial: count, first/last seen, `registered` device (id, site, serial, `is_ha`, `members`), vendor, `requested_sites`, sample line, `different_device_allowed`, `add_ha_member_allowed` / `add_ha_member_needs_mark_ha` / hint; `pending_conflicts` / `pending_lines` totals |
| POST | `/site-devices/conflicts/resolve` | JSON `{"device_key", "kind", "serial"?, "action", "site"?, "device_name"?, "device_id"?, "mark_ha"?, "resolved_by"?}` | `same_device` / `different_device` (needs `site`) / `add_ha_member` (B-12; `mark_ha: true` when the device is not HA yet) replay the group's held lines (`replay` counts, `device`, `resolution`); `discard` needs `IACS_ENABLE_DELETE=true`. 404 unknown group, 409 when the choice cannot apply |
| GET | `/site-devices/conflicts/resolutions` | `limit`, `offset` | Audit trail of resolutions, newest first |

---

## API reference

All responses are JSON unless noted. Purdue levels are accepted as `0`–`5`, `3.5`, `L3.5` or `dmz`
everywhere; anything else gets a uniform 422.

**Paging.** List endpoints take `limit` and `offset` and return the full count in **`X-Total-Count`**:

- `/hosts`, `/assets`, `/sessions`, `/sessions/{id}/details`, `/switch-interfaces`,
  `/firewall-rules`, `/nat-rules` and `/attestation` default to `limit=1000` (maximum 10000).
- `/findings` defaults to `limit=200` (maximum 5000).
- `/topology` uses `host_limit` (default 5000) and `session_limit` (default 10000), and reports
  `X-Hosts-Total` / `X-Sessions-Total` plus `truncated` in the body.

**Errors.** **413** means an upload or request body is too large. Unexpected server errors return a
generic message with an `error id` that appears in the server log, never the exception text.

### Ingest

Every route below except the log routes (`/ingest/syslog`, `/ingest/forti-*`) also **requires
`site`**; on the log routes `site` is optional and maps unknown devices - see
[Sites](#sites-multi-site).

| Method | Path | Key params | Purpose |
|---|---|---|---|
| POST | `/ingest/fortigate-config` | `firewall_name`, `purdue_zone_from/to`, `generate_findings` (true), `populate_approved_hosts`, `baseline_id`/`baseline_name` | FortiGate `show full-configuration` |
| POST | `/ingest/firewall` | `vendor_hint` (cisco\|pfsense\|palo_alto), `firewall_device_name`, `purdue_zone_from/to` | Cisco / pfSense / PAN-OS config, rules + NAT |
| POST | `/ingest/pcap` | `file`, `firewall_id`, `interface_id`, `capture_networks` | PCAP → hosts, sessions, protocol detail, classification, 8.4 check; capture point (VD-02a) |
| GET | `/ingest/pcap/captures` | `site` | PCAP uploads and their capture points (unassociated flagged) |
| POST | `/ingest/pcap/{capture_id}/associate` | body `firewall_id`, `interface_id`, `capture_networks`, `side` | Associate a capture later and re-attribute its hosts |
| POST | `/ingest/pcap-fw` | `firewall_id`, `side` | PCAP with firewall-interface suggestion |
| POST | `/ingest/pcap/{capture_id}/confirm` | body `interface_id`, `side` | Confirm the capture's interface |
| POST | `/ingest/arp` | `format_hint` | ARP table |
| POST | `/ingest/switch` | `vendor_hint` (cisco\|hp\|fortinet), `device_name` | Switch config / VLAN / CDP / LLDP (FortiSwitchOS standalone config) |
| POST | `/ingest/mac-table` | `vendor_hint`, `device_name` | MAC address table |
| POST | `/ingest/syslog` | `vendor_hint` (auto), `device_name` | Multi-vendor syslog |
| POST | `/ingest/forti-syslog` | `device_name` | FortiGate CEF / key=value file |
| POST | `/ingest/forti-event` | JSON body, `device_name` | Single FortiAnalyzer event |
| POST | `/ingest/forti-report` | `file` | FortiAnalyzer CSV report |
| POST | `/ingest/baseline/comms-matrix` | `baseline_name` | Approved communications CSV |
| POST | `/ingest/baseline/approved-hosts` | `baseline_name` | Approved hosts CSV |
| POST | `/ingest/baseline/asset-inventory/preview` | `column_map`, `mapping_id` (form) | Read-only preview of an asset inventory import: columns, suggested fields, checks |
| GET | `/ingest/baseline/asset-inventory/mappings` | `site` | Saved column mappings of the site and the field list |
| DELETE | `/ingest/baseline/asset-inventory/mappings/{id}` | `site` | Remove a saved column mapping |
| POST | `/ingest/baseline/asset-inventory` | `baseline_name`; form `column_map`, `mapping_id`, `save_mapping_as`, `saved_by` | Asset inventory CSV: ip / mac, hostname, device_type, purdue_level, vlan, `zone` (IEC 62443-3-2 zone membership, zone created when missing; a host already in another zone is added to this one too and listed in `zone_multi` - reported by `host_in_multiple_zones`), `sl_c` (1-4) and `sl_c_source` |
| POST | `/ingest/baseline/reviewed-policies` | `baseline_name` | Reviewed policy list CSV |

### Findings

| Method | Path | Key params | Purpose |
|---|---|---|---|
| GET | `/findings` | `status`, `severity`, `category`, `check_name`, `device_name`, `isa62443_sr` (one value each), `q` (text search), `target_sl` (1-4), `fr` (FR1-FR7), `zone_scope` (applies / beyond / no_sl_t / no_zone), `conduit_doc` (intra_zone / documented / undocumented / partial / external), `sort` (`severity` default / `newest`), `limit`, `offset` | List findings, critical → info (newest first within a severity); each row has `fr`, `security_level` and `zone_judgement` (the IEC 62443 zone / conduit / firewall the device resolves to, its SL-T, whether the check applies at it, and `documentation`: inside one zone / documented conduit / no documented conduit / other end in no zone or outside the site; view only) |
| GET | `/findings/export.xlsx` | `site_id`, `include_closed`, `include_excluded` | The findings workbook: one row per finding with the editable columns Status, Name, New note, False-positive reason (shaded) and the read-only context; a *How to use* sheet |
| POST | `/findings/import.xlsx` | `site_id`, `dry_run` (default true), `name`, multipart `file` | Apply an edited workbook: rows matched on the Finding ID, each differing row goes through the Findings page's status rules (refusals reported per row), notes appended with a stamp; importing the same file twice changes nothing |
| GET | `/findings/{id}/config-snippet` | - | The stored configuration lines behind a finding: the policy / interface / admin / VIP / IPsec phase1 / service block it names, else the section its check reads, else (Cisco, PAN-OS, pfSense) the rule's own line - with the firewall, file, upload time and line numbers; `available: false` + `reason` when the finding names no firewall, no text is stored or the object is no longer in the stored config |
| GET | `/firewalls/{id}/config/block` | `site_id`, `key`, `section` (default `system interface`), `vdom` | One block of the stored configuration with its settings as key / value rows: FortiOS `edit <key>` of the section (nested tables summarised), and for `system interface` also Cisco `interface <name>` (or by `nameif`, with its `access-group` bindings), pfSense `<name>` and PAN-OS `<entry name>`; `available: false` + `reason` otherwise |
| GET | `/firewalls/{id}/config` | `site_id`, `download` | The latest uploaded configuration text of a firewall with its secrets masked (`***`: passwords, pre-shared keys, SNMP communities, RADIUS / TACACS keys, private keys, FortiOS `ENC` values) - metadata (file, upload time, line count, masked count) and the text; `download=true` returns a text file. Stored by every config upload (latest only); 404 for configs uploaded before this was added |
| GET | `/findings/linked` | `site_id` and one of `host_id`, `ip` / `mac`, `firewall_id` + `policy_id`, `zone_id`, `conduit_id`; `include_closed` | Findings about one object (address / MAC - a multi-homed device's addresses share its MAC -, a firewall policy by number or rule row, an IEC 62443 zone by name plus its hosts, a conduit's zones plus its attached rules); rows as `/findings`, open + acknowledged by default |
| GET | `/findings/link-counts` | `site_id` | Open + acknowledged findings per host, policy (`firewall_id\|policy_id`), zone and conduit (`count`, `open`, `max_severity`) for list badges |
| GET | `/findings/summary` | `target_sl` (0-4), `fr` | Open counts by severity, category, check, security level and FR, plus `by_status` |
| GET | `/findings/export` | `status`, `severity`, `category`, `check_name` (comma lists), `firewall_id`, `since`, `until`, `target_sl`, `fr`, `zone_scope`, `conduit_doc`, `sort` | CSV in severity order, with evidence flattened into columns (includes `fr`, `security_level`, `iec_zone`, `zone_sl_t`, `zone_verdict`, `zone_documentation`, `shown_severity`, `severity_adjustment`) |
| GET | `/findings/export/summary` | `status` (open), `since`, `until` | CSV pivot per checklist section by severity |
| GET | `/findings/category-reference` | | Every structured check with its SR, FR, security level, checklist row, severity and category |
| PATCH | `/findings/{id}/status` | `status`, `notes`, `acknowledged_by`, `reason` | open → acknowledged → closed, or `false_positive` (`reason` required) |
| POST | `/findings/scan-industrial-writes` | | Re-run checklist 8.4 over stored PCAP data |
| POST | `/reviews/run` | | Run all periodic reviews now. Returns `by_review`, `failed_reviews`, `escalations`, `auto_resolved` |
| GET | `/reviews/rules-not-judged` | `site` / `site_id` | Per firewall, the permit policies the rule-level reviews could not judge (a side with no Purdue level) and why (MP-24) |
| GET | `/reviews/schedule` | | Scheduled reviews: `enabled` (operator switch), `effective` (`on` / `paused` / `disabled` by `IACS_REVIEW_ENABLED`), `cron`, `next_run`, `last_run` (status of the last scheduled firing), `updated_at` / `updated_by` |
| PUT | `/reviews/schedule` | JSON `{"enabled": bool, "changed_by"?: str}` | Pause or resume the scheduled reviews (server-wide, all sites). Stored in the database (`app_settings`), read at every firing, survives restarts; manual runs are not affected |

### Hosts and assets

| Method | Path | Key params | Purpose |
|---|---|---|---|
| GET | `/hosts` | `purdue_level`, `device_type`, `role`, paging | Host list |
| GET | `/hosts/{id}/history` | | Address history (ip, mac, source) |
| POST | `/hosts/mark-stale` | `older_than_days` (30) | Flag hosts not seen recently |
| PATCH | `/hosts/{id}/classification` | `device_type`, `purdue_level` (either or both; level only keeps each host's device type), `unclassified=true` (pin without a level), `apply_to_same_mac` | Manual classification (always wins over automatic) |
| PATCH | `/hosts/{id}/role` | `role` (empty clears it) | Manual functional role |
| POST | `/classify` | | Re-run subnet VLAN inference and automatic Purdue classification |
| GET | `/purdue-levels` | | Level vocabulary (0–5, 3.5) and the device_type reference |
| GET | `/iec-zones` | `site` | IEC 62443-3-2 zones with members, hosts, Purdue levels spanned; hosts in no zone; networks in two zones |
| POST / PATCH / DELETE | `/iec-zones`, `/iec-zones/{id}` | `name`, `sl_t` (1-4), `sl_a` (1-4, achieved), `sl_a_note`, `description`, `owner` | Zone documentation (never affects findings); SL-A below SL-T is flagged |
| POST / DELETE | `/iec-zones/{id}/members`, `/iec-zones/members/{id}` | `kind` host / subnet / interface / fw_zone, `ref`, `move` | Zone members; an asset in several zones is never refused - it is listed (`multi_zone_hosts`, `overlaps`) and reported by `host_in_multiple_zones` / `network_in_multiple_zones`; `move` relocates every placement into this zone |
| GET | `/iec-zones/candidates` | | Interfaces, FortiGate zones, subnets and hosts that can be added |
| POST | `/iec-zones/import` | `source` subnet_zones / fortigate | Seed zones |
| GET / POST / PATCH / DELETE | `/iec-conduits`, `/iec-conduits/{id}` | `zone_a_id`, `zone_b_id`, `name`, `sl_t`, `sl_a`, `sl_a_note` (levels 0-4: SL0 - No Requirements ... SL4 - Advanced Resources), `services` (what the conduit is for: service names / tcp|udp/PORT / any), `sources` (addresses / CIDRs), `description`; on POST also `firewall` + `policy_ids` | Documented conduits with policies and traffic per direction (each found policy marked attached / not attached), attached `rules` (source, destination, allow / deny, services, whether it connects the zones) and `rule_notes`; undocumented zone pairs |
| POST / DELETE | `/iec-conduits/{id}/rules`, `/iec-conduits/{id}/rules/{rule_id}` | `firewall` (name or id), `policy_ids` (list or "20, 21"), `vdom`, `note` | Attach / detach firewall rule numbers to a conduit (every policy must exist on the firewall; documentation only) |
| GET | `/iec-zones/export` | `table` zones / assets / conduits | CSV (UTF-8 BOM) |
| GET | `/assets` | `purdue_level`, `device_type`, `role`, `criticality`, `approved`, `site`, `search`, `inventory` (`listed` / `unlisted` / `unknown`), paging | IACS asset inventory; each row carries `in_inventory`, `inventory_evidence` and the IEC 62443 zone (`iec_zone`, `iec_zones` with SL-T and basis: host member, else the zone of its subnet / interface); `inventory=excluded` / `all` and `include_excluded=true` show the hosts excluded from the inventory (left out by default; also on `/assets/export`, which carries `inventory_excluded` / `_reason` columns); `PATCH /assets/{id}` takes `inventory_excluded` + `inventory_excluded_reason` + `inventory_excluded_by` |
| PATCH | `/assets/{host_id}` | inventory fields, `approved`, `approved_by`, `last_reviewed_by`, `sl_c` (1-4 / `none`), `sl_c_source`, `iec_zone` (zone name: the host becomes its host member, zone created when missing; empty removes the host's own membership) | Update inventory or approve; SL-C = IEC 62443-4-2 capability security level (documentation only) |
| PATCH | `/firewalls/{id}/sl-c` | `sl_c`, `sl_c_source` | SL-C of a firewall / routing switch (documentation only) |
| GET | `/assets/export` | `purdue_level`, `approved`, `criticality`, `site`, `inventory` | Inventory CSV (UTF-8 BOM) with `in_inventory` / `inventory_evidence` and `zone` (IEC 62443; the import maps it back) columns |
| GET | `/sessions` | `protocol`, paging | Observed sessions |
| GET | `/sessions/{id}/details` | paging | Decoded protocol frames for one session |
| GET | `/switch-interfaces` | `device_name`, paging | Switch ports, VLANs and neighbours |

### Firewalls, rules and NAT

| Method | Path | Key params | Purpose |
|---|---|---|---|
| GET | `/firewall-devices` | `purdue_zone_from`, `purdue_zone_to`, `vendor` | Devices with their boundary, active and disabled rule counts, interfaces |
| PATCH | `/firewall-devices/{id}/boundary` | `purdue_zone_from`, `purdue_zone_to` | Set or correct a device's Purdue boundary |
| GET | `/firewall-rules` | `device_type`, `device_name`, `action`, `enabled`, `firewall_device_id`, `firewall_id`, paging | Parsed rules (including `last_matched`) |
| GET | `/firewall-rules/shadowed` | `device_name`, `firewall_device_id`, `include_partial` (true), `generate_findings` | Full, partial and duplicate shadows, plus informational exceptions |
| GET | `/firewall-zones` | `device_name` | FortiGate interface → zone map |
| GET | `/nat-rules` | `firewall_id`, `firewall_device_id`, `nat_type` (dnat\|snat), paging | Parsed NAT |

### Topology and reachability

| Method | Path | Key params | Purpose |
|---|---|---|---|
| GET | `/topology` | `host_limit`, `session_limit` | Graph: host nodes, session edges, firewall boundaries |
| GET | `/topology/ports` | `site_id` | Firewall Ports: every firewall / routing switch of the site as its front - `ports` in config order (physical ports; an aggregate as one port naming its `members`, read from the stored config; VLAN sub-interfaces ride on their parent port; loopbacks / tunnels are not ports), each with `kind_label` (untagged · access, trunk · n VLANs, access + n VLANs, aggregate …, WAN · egress leg, HA heartbeat, dedicated management, unused), status, role and its `subnets` (interface name, VLAN tag, address, network, alias, FortiOS zone, interface level or the Subnets & Zones declaration, host count) - and `links`: for every pair of interfaces with an enabled permit policy between them (zones expanded to their member interfaces) the services (`tcp/502`, `ALL`) with a kind (cleartext, mgmt, cleartext-mgmt, any, icmp, ok), the policy numbers and how many captured sessions used the service, `into_ot` when the destination is L0-L2 and the source is not. View only |
| GET | `/topology/subnets` | `site_id` | Network Topology: the site's hosts in lanes by subnet / VLAN (firewall and routing-switch interface networks, capture segments, switch VLANs, inferred /24s), each host with its function (device-type group), per-lane function counts and a *mixed* flag, the Subnets & Zones declaration, `intra_sessions` / `intra_protocols` (sessions inside the lane), per host its observed `flows` (peer, peer lane, direction, protocol / port, packets, same lane or what sits between; capped at `max_flows_per_host`), `separators` - for every pair of lanes with observed sessions what sits between them (firewall with its policies, routing switch, same layer-2 segment = flat, nothing known; WAN legs, tunnels and disabled interfaces make no lane) - and `egress`: the External comms flows grouped by destination (name / organisation, category, `private` = the corporate side beyond the firewall (private addresses outside every known network that the captures only saw behind a router - no MAC of their own), addresses, review status, the inside sources with their lane and an `ot` mark), `by_lane` egress counts (sessions, attempts, OT, Internet / private destinations) and the firewall WAN interfaces; `separators[].through[]` carries each firewall's own `policies` / `permit_policies` and `firewalls` lists the site's firewalls with their lane counts (for the page selector). Public addresses are egress destinations, not lane hosts. View only |
| GET | `/diff` | | Observed sessions vs permit rules: `unexpected_traffic`, `unused_rules`, `unresolvable_rules` |
| GET | `/reachability` | `src_ip`, `dst_ip`, `dst_port`, `protocol`, `src_level`, `dst_level` | Level-to-level matrix. Each cell's `overall` is one of `permitted`, `partial`, `denied`, ... |
| GET | `/reachability/path` | `src` (required), `dst` or `dst_level`, `dst_port`, `protocol` | Hop-by-hop path with first-match rule, NAT-aware |
| GET | `/topology/state` | | Multi-firewall state, interfaces and pending link proposals |
| GET | `/topology/firewalls` | | Lightweight firewall picker list |
| POST | `/topology/confirm-link` | body `iface_a_id`, `iface_b_id` | Confirm a link (then runs suggestions and cross-FW checks) |
| POST | `/topology/set-interface-side` | body `interface_id`, `side`, `zone_label`, `purdue_level`, `clear` (list of fields to reset) | Operator labels on an interface |
| POST | `/topology/set-upstream` | body `firewall_id`, `upstream_firewall_id`, `purdue_level_ingress/egress`, `topology_confirmed` | Firewall chain. Cycles are rejected. |
| POST | `/topology/suggest-purdue` | | Re-run interface Purdue suggestions |
| POST | `/topology/run-checks` | | Re-run the cross-firewall checks |
| GET | `/management/networks` | | Declared management / engineering networks, interfaces / VLANs with their classification, suggestions (docs/management-networks.md) |
| POST | `/management/networks` (201) | body `kind` (subnet / host / vlan / name), `purpose` (management / engineering), `cidr`, `role` (admin_ws / jump_host / engineering_ws / ntp_server; a host may hold several roles, one declaration each), `vlan_id`, `firewall_id`, `name`, `is_management`, `finding_id`, `recheck` | Declare; re-runs the affected checks and reports what closed. A declared `ntp_server` is a site service: time sync to it (port 123) from any level is not an upward skip, a level bypass or an IT dependency |
| DELETE | `/management/networks/{id}` | `recheck` | Remove a declaration (its findings come back) |
| GET | `/management/fix-options` | `finding_id` | Declarations that would resolve a management finding |
| POST | `/management/recheck` | | Re-run the management checks |

### Baselines and attestation

| Method | Path | Key params | Purpose |
|---|---|---|---|
| GET | `/baselines` | | Baselines, active one first |
| POST | `/baselines/{name}/activate` | | Make a baseline active |
| GET | `/attestation` | `checklist_id`, `current_only`, paging | Attestation records, without proof bytes |
| POST | `/attestation` (201) | form `checklist_id` (1.1–1.6), `attested_by`, `attested_at`, `notes`, `baseline_name`, file `proof` (≤20 MB) | New attestation. Demotes the previous current record. |
| GET | `/attestation/{id}/proof` | | Download the proof file |

### Reports, diagnostics and health

| Method | Path | Key params | Purpose |
|---|---|---|---|
| GET | `/reports/compliance.pdf` | `layout` (`lrqa` = the LRQA compliance report, default; `public` = the public compliance report), `baseline`, `include_closed` (adds a *Closed Findings* section: closed date, who, notes - the findings in scope stay open + acknowledged), `site`, `target_sl` (0-4), `include_zones` (default true), `all_checks` | Compliance PDF, the same as `generate_report.py` |
| GET / PUT | `/reports/details` | `site_id`; PUT body `client_name`, `project_name`, `author`, `author_email`, `version`, `classification`, `distribution` ([{name, role, email, side: client / assessor}]), `revisions` ([{version, date, status}]), `constraints`, `by` | The site's report details printed on the PDF's cover (Prepared For / Project / Author / Date, classification and version in the footers), Distribution List (the client points of contact - `side: client`, any number - first, then the assessor team), Revision History and the Engagement Particulars' constraints paragraph (Reports page, *Report details*). GET returns the defaults (version 1.0, "Confidential Security Data (CSD)") until something is stored; PUT replaces every field |
| POST | `/reports/audit-checklist` | multipart `file` (the filled-in `ISA62443_Master_Audit_Checklist.xlsx`), `format` (`pdf` default, `csv`, `json` = preview), `scope` (`findings` default: Non-compliant / Partially compliant and checks with a recorded finding, severity or recommendation; `assessed`; `all`), `order` (`severity` default, `checklist`), `site` / `site_id` (optional: the site's Report details fill the cover, distribution list, revision history and constraints), form field `details` (JSON given for this report, overriding the site's: `client_name` = Prepared for, `author`, `report_date` YYYY-MM-DD, `pocs` [{name, role, email}] = the client's points of contact (any number), `consultants` [{name, role, email}] = the LRQA consultants (any number), plus `project_name`, `version`, `classification`, `constraints`, `distribution`, `revisions`) | Owner 2026-10-24: the ISA/IEC 62443 audit report from the Master Audit Checklist workbook. One report finding per checklist row - the *Check title* is the title, the *Audit check* the details, with the *Domain* and the auditor's *Finding / Observation*, *Evidence Reviewed*, *Severity*, *Recommendation*, *Owner* and *Target Date*; the PDF uses the LRQA layout (cover, contents, distribution list, revision history, engagement particulars with the compliance-by-domain table, findings, one analysis page per finding, appendix with every check's status); the CSV has one line per finding in report order. Nothing is stored. Same output as `generate_audit_report.py` |
| GET / PUT | `/reports/check-selection` | `site_id`; PUT body `exclude` ([{check_name, reason}] or names), `include` (names), `by` | Every check grouped (FortiGate configuration (CIS) = every FortiGate config check, rule reviews, chains & access paths, zones, syslog, PCAP sessions, switches, network & asset reviews) with whether it is in the site's compliance report, the reason it is not and its open findings; PUT leaves checks out / puts them back. The findings of an excluded check are hidden throughout the application - `/findings`, `/findings/summary`, the exports, `/findings/linked`, `/findings/link-counts`, the `/sites` counts - unless `include_excluded=true` (rows then carry `excluded_from_report`); the check keeps being evaluated. The PDF leaves excluded checks out (findings, severity summary, coverage) and lists them in *Checks Excluded from this Report*; `all_checks=true` on the PDF (or `--all-checks`) ignores the selection |
| GET | `/diagnostics` | | Unknown check names and a summary of the last review run (per process) |
| GET | `/health` | | `{"status":"ok"}` (used by the Docker HEALTHCHECK) |

### UI pages (HTML, excluded from OpenAPI)

`GET /` (307 → `/ui`), `/ui`, `/ui/upload`, `/ui/findings`, `/ui/topology`, `/ui/fw-topology`,
`/ui/attestation`.

### Delete endpoints (off unless `IACS_ENABLE_DELETE=true`)

While deletes are turned off, every endpoint here returns **403**. Each delete is logged with what it
removed.

| Method | Path | Params | Effect |
|---|---|---|---|
| DELETE | `/findings/{id}` | | Delete one finding. Closing it is usually the better choice. |
| DELETE | `/attestation/{id}` | | If it was current, the newest remaining record becomes current |
| DELETE | `/firewall-devices/{id}` | | Device plus its rules and NAT. Findings keep their evidence and get `rule_id = NULL`. |
| DELETE | `/baselines/{name}` | `force` | Returns 409 if the baseline is active or has attestations, unless `force=true` |
| DELETE | `/hosts/{id}` | `force` | Returns 409 while sessions reference the host, unless `force=true` (deletes those sessions) |
| DELETE | `/sites/{id}` | `force` | 409 for the last site, or while the site has data unless `force=true` (deletes all of it) |
| DELETE | `/site-devices/{id}` | | Unregister a log device; its stored events stay |

---

## Web UI

**Console: `/ui`** (`ui/index.html`). A single-page app with these sidebar sections:

| Group | Section | What it does |
|---|---|---|
| Ingest | Upload Data | Every upload form above, with vendor pickers (incl. *FortiSwitch (standalone)* for FortiSwitchOS configs) and per-upload stats |
| Ingest | Devices | Registered log devices (add, remap, delete; HA clusters show an *HA mode · group* badge, the member serials with source / last seen, and *Add member serial* with an in-row confirmation), **Conflicts** (B-11: per conflict the device, both serials, registered site, counts, sample line and *Same device* / *Different device - pick site* / *Discard* (B-12: *Add as HA member* first for an HA member candidate) with an in-page confirmation and the replay result) and **Unmapped devices** (held lines per device, *Map to site* with replay result, discard, purge); the nav badge counts held unmapped + conflict lines |
| Monitoring | Findings | Filter findings (findings of checks left out of the report are hidden; *Show findings of excluded checks* lists them, marked); *Prev* / *Next* step through them one at a time (crossing into the previous / next page at its edge; "finding n of N" beside the page range); clicking a finding shows its details while it stays where it is and keeps focus, and saving its status keeps the list in place; change status, see last seen and occurrences, run reviews now; each device finding shows its IEC 62443 zone, whether the check applies at that zone's SL-T (Zone SL-T filter) and, for a finding with two ends, whether the path is inside one zone, over a documented conduit or between zones with no conduit (Conduit filter); a finding on a documented conduit whose services and sources cover it is shown one severity step lower (↓ badge with the reason; the recorded severity is unchanged); a finding about a firewall config or rule has a *Configuration lines* block with the stored config lines behind it (the policy / interface / admin / VIP block, the section the check reads, or the Cisco rule line; *Open in config* opens the drawer on those lines, highlighted); a finding about a host has *Edit asset* buttons that open the asset in a side drawer (inventory fields, Classify and the host's findings; the record keeps the focus, Escape returns it) - saving there re-runs the site's reviews so the findings it fixes close. The same findings section (status, name, notes, false-positive reason inline) is on the Inventory asset panel (with a Findings column badge), the Host Topology host panel, the Zones & Conduits zone panel (badges on zones and conduits) and behind a ⚑ badge on each Firewall Devices policy |
| Topology | Network Topology (sub-item of Host Topology) | The network as it is, for flat networks without a mature Purdue posture: one lane per subnet / VLAN (firewall / routing-switch interface networks first, then capture segments, switch VLANs, inferred /24s and inferred /24s - these can be hidden), disabled (administratively down) interfaces make no lane; each host as a card coloured by its **function** (controllers, HMI / SCADA, engineering / jump, servers, infrastructure, IT, remote, unknown) with its Purdue level if any; lane header with interface names / aliases, the label or declaration, function counts, *mixed functions* (controllers share the network with other functions) and *flat with …* (same layer-2 segment as another subnet); the side panel lists the lanes that exchange traffic and what sits between them (firewall with permit / total policies, routing switch, flat, nothing known); a card's *↔ n* badge (or the F key on a focused card) lists the host's observed conversations - peer, protocol / port, same lane or via firewall / routing switch / flat / nothing - with cleartext logins marked; a card opens the asset drawer; *Declare…* records the subnet's Purdue level / zone (Subnets & Zones; level and optional zone name, no reviewer name). The last lane is **Egress / outside the site**: one card per destination (name or organisation, category, review state), *Internet* first and *Beyond the firewall (private addresses)* as a sub-group, red when an OT host reaches it; its *↔ n* badge lists the inside sources with their lane; clicking a card opens the review drawer (Approve / Remove per source or for every host - the External comms records; an approval never closes an OT host's egress finding); the header names the WAN leg(s) and counts destinations, approved ones and OT sources; *show egress lane* toggle. A site with several firewalls gets a **firewall selector**: the chosen firewall's lanes are outlined, the others dimmed, and the connections panel lists its lane pairs first with its own policy numbers, the pairs through other devices dimmed |
| Topology | Firewall Ports (sub-item of Host Topology) | Each firewall / routing switch as its front: the ports in config order (aggregates as one port naming their members; WAN marked as the egress leg; HA and management ports named; disabled ports hidden unless *show disabled ports*), per port its kind (untagged / access, trunk · n VLANs, unused) and one chip per subnet riding on it - VLAN tag, network, Purdue label or declaration, FortiOS zone, alias, host count; a chip opens the lane on Network Topology. Hover or focus a port and the other ports light up with the services the enabled permit policies allow (green border = into the hovered port, orange = out of it, both colours = both ways, faded = none), one chip per service (`tcp/502`, `ALL`) with cleartext / management services red and `ALL` amber, inter-VLAN permits on the same trunk listed under the port itself; click pins a table (direction, peer port / VLAN, services, policy numbers linking to the policy on Firewall Devices, sessions seen in captures per service, notes such as *into OT* or *management protocol*). Permits only; *table view* lists every port / interface / VLAN / subnet / zone / level / hosts as rows; a FortiLink port lists the FortiSwitches it manages ("FortiSwitch: …") |
| Topology | Host Topology | Purdue swimlanes from `/topology`, stale badges, address history, truncation notice; drag a host card onto another level lane to set its level (confirmation bar; every address of the card's MAC moves, the device type is kept; empty L5 / L3.5 lanes appear while dragging), or onto Unclassified to pin it without a level (automatic classification leaves it alone) or, for a hand-classified host, return it to automatic classification. Multi-homed devices (one MAC with addresses in two or more subnets; routers / switches / firewalls excluded) show one red card per address in its own lane, a "same device as ..." badge and a red dashed link labelled *DMZ bypass* (IT side L4 / L5 joined to L3 or below), *bypass Lx↔Ly* or *multi-homed*; dragging such a card moves only that address |
| Topology | Firewall Devices | Boundaries (editable), active/disabled rules, NAT, last-matched drill-down. *Config* on the card opens the last uploaded configuration (passwords, keys and communities masked as `***`) in the side drawer: line numbers, folding `config … end` sections, find (Enter steps through the matches), go to line, download. The card counts policies (one per policy line, as the drill-downs group them; the tooltip gives the expanded rows) and, when any, the VPN policies - a policy with an SSL, dial-up IPsec, site-to-site IPsec or L2TP tunnel as a side; *VPN (n)* opens the rules filtered to them (*VPN policies only*), each line badged "VPN · <kind> in/out" with the SSL-VPN / dial-up user groups that policy names (and their IT / vendor class from Mgmt & Engineering). The NAT drill-down likewise shows one line per NAT policy (or VIP) - its original addresses (with the host hover and Classify level / zone), mapped addresses, ports and the translation count; click to expand (same *One line per policy* setting). The rules drill-down shows one line per policy number by default (its sources, destinations and services together; click to expand the rows) - untick *One line per policy* for one row per expanded source / destination / service. Hovering (or focusing) a zone / interface name in the Zones column shows its networks (from the uploaded config) and the inventory hosts on them; hovering a Source or Destination cell (policy lines and single / expanded rows) lists every consolidated address with the inventory host behind it (a network with its host count). Its *Classify level / zone…* button (or Enter on the cell) opens a dialog that saves one Purdue level + zone name for the ticked IPv4 values as Subnets & Zones declarations (a host is a /32); hosts that keep their own level (manual, protocol role, a narrower declaration) are listed, and *Run reviews now* applies it to the findings |
| Topology | FW Topology Builder (first in the group) | PCAP-to-interface assignment, link confirmation, sides, upstream chain, Purdue suggestions, cross-FW checks. Shows enabled interfaces only by default; *Show disabled interfaces* adds the administratively-down ones (FortiOS `set status down`, Cisco `shutdown`) greyed out with a "disabled" badge (each column header counts them). Selecting an interface shows **Settings from the config**: a key / value table of its stored configuration block (type, VLAN id and parent, IP and secondary IPs, `allowaccess` with HTTP / Telnet / SNMP / FTP in red, role, alias, description, status, DHCP, members ...; Cisco: the `interface` stanza with `nameif`, `security-level`, `ip address`, `shutdown` and its `access-group` bindings; pfSense / PAN-OS: the interface element), the raw block collapsed below and *Open in config* on it. An interface's config alias (FortiOS `set alias`) is shown in grey under its name - also on the Firewall Devices card, in the rules Zones column next to an interface name (e.g. `vlan_20 Process Control`) and in the zone hover; display only |
| Topology | Mgmt & Engineering | Declare management (infrastructure admin) and engineering (programming L0-L2 devices) networks, trusted hosts (admin workstation, jump host, engineering workstation) and VLANs; reclassify firewall interfaces / zones; confirm name-based suggestions. Open management and industrial-write findings also offer one-click fixes on the Findings page |
| Compliance | Reachability | Level matrix (including `partial`), per-cell paths, host path lookup with NAT |
| Compliance | Access Review | Every path the firewall rules allow between Purdue levels with the captured traffic on it, flags, classification and the report selection; rows through a site-to-site IPsec tunnel are bounded by the tunnel's phase 2 selectors (flag `tunnel_selector`, the wider policy text kept as the policy scope); rows that differ only in the destination (or source) host are rolled into one line with the count, the addresses, per-status traffic counts and group-wide classify / include (*Roll up similar paths*, on by default; `group_dst` / `group_src` on `GET /access-paths`) |
| Compliance | Shadow Rules | Shadowed, duplicate and conflicting rules per device. One card per policy pair by default (shadowed policy + the policy, or union of policies, shadowing it): "N of the M rows of policy X" ("all rows" = the whole policy is dead or a duplicate), the distinct sources / destinations / services of each side, *Show the N row pairs* for the per-row detail - untick *One card per policy pair* for one card per expanded row pair |
| Compliance | Attestation | Zone documentation 1.1–1.6: submit, view current and history, download proof |
| Compliance | Zones & Conduits | IEC 62443-3-2 zone documentation (Subnets & Zones is its sub-item in the menu): zone and conduit SL-T and achieved SL-A (flagged when below), every level picked from SL0 - No Requirements ... SL4 - Advanced Resources, SL-A on the Add zone form, in the zones table and on the Document conduit card; conduits named to their zones and firewall rule numbers (chips with a hover card: source, destination, allow / deny, protocols / ports; found policies not attached are marked); hosts' and firewalls' SL-C (IEC 62443-4-2) against the zone / conduit SL-T; zones with SL-T whose members are hosts, subnets, firewall interfaces / VLAN sub-interfaces and FortiGate zones at any Purdue levels; documented conduits per zone pair with the permitting policies and observed traffic per direction; zone pairs that communicate without a documented conduit; import from Subnets & Zones / FortiGate zones; CSV exports. Documentation only - never changes findings or levels |
| Assets | Inventory | *Not an inventory asset?* on the asset panel excludes a host from the inventory with a reason and a name (scanner, broadcast / virtual address, transient device): it leaves the list and the CSV export only - Host Topology (marked "not an inventory asset"), Reachability, Access Review, sessions, zones and the findings keep showing it - and `unknown_device` counts it as reviewed (the finding closes at the next review); the Inventory filter *Excluded* lists them (badge "excluded") with *Include in the inventory again*. Asset inventory editing and approval (incl. SL-C and its source, and the IEC 62443 zone - Zone column, filter and an editable zone name), Import CSV with a column mapping (saved per site), CSV export, mark stale hosts; Inventory column and filter: listed (Asset Inventory CSV, Approved Host List, approved on the page), not in any inventory, or not in any inventory and unclassified. VLAN column: from a switch MAC table, an 802.1Q capture or the inventory CSV; otherwise from the firewall / routing-switch VLAN interface whose subnet holds the host (FortiOS `set vlanid`, shown "from FW-OT vlan_20"), else the /24 guess |
| System | Reports & Diagnostics | *Report layout* (LRQA compliance report / Public compliance report) and the *Report details* card (client, project, author, version, classification, client points of contact, assessor team, revision history, constraints - printed on the LRQA cover and front pages); compliance PDF download (target security level SL0 - No Requirements ... SL4 - Advanced Resources, or all levels; *Ignore the check selection*; closed findings in their own section; a *Shadowed and Redundant Rules* section listing the shadow_rule findings as rule pairs), **Findings workbook** (xlsx export of the site's findings, edit Status / Name / New note / False-positive reason in Excel, preview and apply the import), **Audit checklist report** (upload the filled-in ISA/IEC 62443 Master Audit Checklist workbook: check it, download the audit report PDF in the LRQA layout or the findings CSV; one finding per checklist row; the card asks for *Prepared for*, the author, the date of the report, the client points of contact and the LRQA consultants - any number of each, pre-filled from *Report details*), **Checks in the report** (every check grouped by source - or by checklist section - with tri-state group checkboxes, search, an optional reason and your name; saved per site), run periodic reviews, `/diagnostics` |

**Sites.** The console's sidebar has a global **Site** selector: always one site (there is no
*All sites*; the choice is remembered in the browser, and with nothing remembered - or a
remembered site that was deleted - the default / first site is selected). Every page, including
the standalone Findings, FW Topology Builder, Attestation and Host Topology pages, shows only the
selected site's data (`?site_id=<id>` on every request). The cross-site views are the Sites
overview and the PDF's explicit *All-sites roll-up* option. Every upload form (Upload Data, FW Topology Builder PCAP, Attestation) has a
required site picker with an inline **+ New site** action; on log uploads the picker is the
optional **Map unknown devices to** site, and the result shows the routing summary (per site,
held, new mappings, conflicts).

The **Sites overview** page (Monitoring group) is the read-only roll-up: a card per site with open
findings by severity, firewalls / hosts, last review and upload, active baseline and attestation
state, an *Open findings* button (selects that site and opens Findings) and a per-site *PDF report*
link. The Site selector does not filter it.

`/ui/topology` is the console's Host Topology on its own, full screen (same lanes, cards, zones,
Internet card and Classify control; site selector shared with the console).

**Standalone pages** (older single-purpose views, still maintained): `/ui/upload`, `/ui/findings`,
`/ui/fw-topology` and `/ui/attestation`. `/ui/upload` has the same required site
picker; the others have a site filter shared with the console (on `/ui/attestation` and
`/ui/fw-topology` it is also the site that saves / PCAP uploads go to, so pick one there first).

All pages call the API on the origin that served them. Opening the HTML files from disk isn't
supported; the console shows a banner if you try. API data is treated as untrusted and escaped
before rendering, and the browser smoke suites check for this (see below).

---

## Installation and deployment

### Bare metal / VM: `install.sh`

```bash
sudo bash install.sh                           # installs to /opt/iasc_monitor, binds 127.0.0.1:8000
sudo bash install.sh --prefix /srv/iasc --host 0.0.0.0 --port 8888 --user iasc
sudo bash install.sh --no-service              # no systemd unit
```

The installer:

1. Installs system packages (apt, dnf or yum: python3, venv, libpcap).
2. Requires Python ≥ 3.11.
3. Copies the tree with rsync, or tar as a fallback. Copying never deletes anything: `*.db*`, `.env`,
   `.venv` and `dist` are excluded, so an upgrade keeps the production database and settings.
4. Creates `<prefix>/.venv` and installs `requirements.txt`.
5. Writes `<prefix>/.env` on the first install only. It contains `IACS_DATABASE_URL`,
   `IACS_ALLOWED_ORIGINS`, `IACS_HOST` and `IACS_PORT`.
6. Runs the migrations. If an existing database has tables but no `alembic_version` (a **legacy
   unversioned database**), it is stamped at `0001baseline0` first. Then `alembic upgrade head` runs.
7. Creates the `iasc` system user and a hardened systemd unit `iasc_monitor.service`. The unit uses
   `EnvironmentFile=<prefix>/.env`, `ExecStartPre=alembic upgrade head` and
   `uvicorn --workers 1`, and sets `ProtectSystem=strict`.

Manage the service with `systemctl status|restart iasc_monitor` and `journalctl -u iasc_monitor -f`.

### Docker

Step-by-step guide (install, upgrade, backup/restore, troubleshooting): **docs/docker-install.md**.

```bash
docker compose up -d --build     # 127.0.0.1:8000/ui, SQLite on the named volume iasc_data -> /data
docker compose exec iasc-monitor python backup_db.py      # online backup -> /data/backups/
docker compose -f docker-compose.yml -f docker-compose.dev.yml up --build   # debugging (dev target)
```

- **Dependencies are locked.** The image installs `requirements-lock.txt` only (exact versions,
  `--no-deps`): the set the test suite was verified with.
  `requirements.txt` pins the direct dependencies to the same versions.
- Targets: `runtime` (default; non-root `iasc`, uid 1000, `/health` HEALTHCHECK, one uvicorn
  worker) and `dev` (adds pytest and the test tools; source bind-mounted with `--reload` by
  `docker-compose.dev.yml`, database in `./data`).
- `/data` is a declared `VOLUME`: database + WAL, scheduler lock, upload spool (`TMPDIR=/data/tmp`,
  cleared at start) and backups. It survives restarts, host reboots, `docker compose down` and image
  upgrades; only `docker compose down -v` / `docker volume rm iasc_data` delete it.
- `docker-entrypoint.sh` checks `/data` is writable, stamps an unversioned database
  (`IACS_LEGACY_DB_REVISION`) and runs `alembic upgrade head` before `uvicorn`.
  `IACS_SKIP_MIGRATIONS=true` skips the migrations.
- Base image: `python:3.11-slim-bookworm` (`ARG PYTHON_VERSION=3.11`; verified on 3.11.15). For an
  immutable build pin the digest: `--build-arg PYTHON_BASE=python@sha256:<digest>`.
  Behind a TLS-inspecting proxy: `PIP_CA=/path/ca.pem ./build.sh` (passed as a build secret).

### Source tarball: `make-dist.sh`

```bash
bash make-dist.sh 1.2.3 --out ./dist   # -> dist/iasc_monitor-1.2.3.tar.gz + .sha256
```

The version comes from the argument, then a git tag, then a `VERSION` file, and otherwise `dev`. The
tarball contains `app/`, `ui/`, `alembic/`, `docs/`, `sample_data/`, `alembic.ini`, the
requirements and lock files, `install.sh`, `make-dist.sh`, `generate_report.py`, `backup_db.py` and `README.md`. It doesn't
contain tests or the Docker files. The `.sha256` file records the bare filename, so you can verify
it with `sha256sum -c`. Unpack the tarball and run `sudo bash install.sh`.

### PostgreSQL

Set `IACS_DATABASE_URL=postgresql+psycopg2://user:password@host:5432/iasc` (the driver is
`psycopg2-binary`, already in `requirements.txt`), then run `alembic upgrade head`. JSON columns use
JSONB on PostgreSQL, and timestamps are stored as naive UTC on every backend.

### SQLite specifics

Every connection sets `PRAGMA foreign_keys=ON` (see `IACS_SQLITE_FOREIGN_KEYS`) and
`busy_timeout=30000`. File databases use **WAL** journal mode, so a long PCAP ingest doesn't block
reads. Back up the `-wal` and `-shm` files along with the `.db` file, or checkpoint first.

---

## Database migrations

The Alembic chain lives in `alembic/versions/`. It runs from the root to the current head:

```
0001baseline0 (full schema) -> 946998cf677b -> a1b2c3d4e5f6 -> b2c3d4e5f6a7 -> c3d4e5f6a7b8
  -> d4e5f6a7b8c9 (reconcile legacy schema) -> e5f6a7b8c9d0 -> f6a7b8c9d0e1 -> a8b9c0d1e2f3
  -> b9c0d1e2f3a4 (Purdue L3.5) -> c0d1e2f3a4b5 (head: sites)
```

```bash
alembic heads                    # c0d1e2f3a4b5 (head)
alembic current
alembic upgrade head
alembic upgrade head --sql       # offline: render SQL (e.g. to review PostgreSQL DDL)
alembic -x url=postgresql+psycopg2://... upgrade head
```

The URL is resolved in this order: a programmatic connection or URL, then `-x url=`, then
`IACS_DATABASE_URL`, then the default `sqlite:///./iasc_monitor.db`.

- **New database:** `alembic upgrade head` builds it from empty. If the app creates it on first
  start instead, `init_db()` stamps it at head.
- **Legacy unversioned database** (tables but no `alembic_version`, created by `create_all` before
  migrations were tracked): run `alembic stamp 0001baseline0` and then `alembic upgrade head`.
  `install.sh` and the Docker entrypoint do this automatically. At startup, `init_db()` logs a
  warning for an unversioned database or one that is behind head.
- **Reconcile revision `d4e5f6a7b8c9`** is additive only. It creates any table, column or index
  that a legacy schema is missing, so stamping at the baseline is safe for any legacy database.
- **Sites revision `c0d1e2f3a4b5`** creates `sites`, inserts the *Default* site and gives every
  root table a `site_id` (backfilled to Default, then NOT NULL, FK `sites.id`, index
  `ix_<table>_site_id`). On a legacy upgrade the reconcile revision runs first and has usually
  already added `sites` (empty) and the `site_id` columns as NULLable; `c0d1e2f3a4b5` detects that,
  backfills and tightens. On SQLite the NOT NULL/FK step rebuilds each root table (batch mode), so
  take a backup and expect the upgrade to take a little longer on big databases. Offline `--sql`
  renders the PostgreSQL DDL; on SQLite it needs an online upgrade.
- **Convention:** every revision after the baseline must be **idempotent**. It inspects the live
  schema and only adds what is missing. Use the helpers in `alembic/iasc_migration_utils.py`
  (`has_table`, `has_column`, `has_index`, `has_check_constraint`, ...), which also behave correctly
  in offline `--sql` mode.
- After upgrading from an older release, **re-ingest firewall configs**. The `dst_port` format and
  the handling of disabled and negated rules changed. The [remediation tracker's upgrade
  notes](docs/code-review-remediation.md#upgrade-notes-for-existing-installs) have the details.

---

## Audit checklist report

The ISA/IEC 62443 audit report built from the filled-in Master Audit Checklist workbook
(`ISA62443_Master_Audit_Checklist.xlsx`, sheet *Master Checklist*: 149 consolidated checks with the auditor's
Status, Maturity Level, Finding / Observation, Evidence Reviewed, Severity, Recommendation, Owner and Target Date).
Nothing comes from the database: the workbook is the input (owner 2026-10-24).

```bash
python generate_audit_report.py CHECKLIST.xlsx [--out FILE.pdf] [--csv FILE.csv] [--no-pdf] [--scope findings|assessed|all] [--order severity|checklist] [--client NAME] [--project NAME] [--author NAME] [--version V] [--classification TEXT] [--constraints TEXT]
```

| Option | Default | Meaning |
|---|---|---|
| `CHECKLIST.xlsx` | | The workbook. The *Master Checklist* sheet is used when present, otherwise the first sheet whose header row has *Check title*, *Audit check* and *Status*; columns are matched by header text, a missing column is a note |
| `--out` | `isa62443_audit_report.pdf` | The PDF: cover (with the LRQA logo `ui/lrqa_logo.png`), contents, distribution list, revision history, engagement particulars (scope, constraints, finding summary, compliance by domain = the workbook's Summary sheet recomputed), 4 Findings (one row per finding), 5 Analysis (one page per finding: Master ID, domain, status, severity, maturity, owner / target date, FR / Min SL; *Audit Check* = the finding details; *Finding / Observation*, *Evidence Reviewed* (+ the checklist's suggested evidence), *Recommendation* as the auditor wrote them; *Further Reading* = covered Req IDs, source standards, NIST reference), 6 Appendix (every check's status, the severity / status scale, standards) |
| `--csv` | | Also write the findings as CSV (UTF-8 with BOM): Section, Master ID, Domain, Finding title, Finding details, Status, Maturity level, Severity, Finding / Observation, Evidence reviewed, Suggested evidence, Recommendation, Owner, Target date, FR, Min SL, Audit scope, Conditional, Covers, Source standards, NIST reference |
| `--scope` | `findings` | `findings`: rows rated Non-compliant or Partially compliant, plus rows with a recorded finding, severity or recommendation that are not Compliant / Not applicable (reported as Not assessed, with a note); `assessed`: every row but Not assessed; `all`: every row |
| `--order` | `severity` | Analysis order: High, Medium, Low, unrated (Non-compliant before Partially compliant within a severity), then checklist order; or `checklist` |
| `--client`, `--author`, `--date` | asked | *Prepared for*, *Author* and the *Date of the report* on the cover. On a terminal the program asks for each one not given (Enter keeps the default: author IACS_Monitor, today's date) |
| `--poc 'NAME; ROLE; EMAIL'`, `--consultant 'NAME; ROLE; EMAIL'` | asked | The Distribution List: the client's points of contact and the LRQA consultants, any number of each (repeat the flag). On a terminal the program asks for them, one person at a time, until an empty name |
| `--no-prompt` | | Never ask; use the flags and defaults (what the console and tests do) |
| `--project`, `--version`, `--classification`, `--constraints` | | The other cover / footer / constraints text (the console takes them from the site's *Report details*) |

## Compliance report

```bash
python generate_report.py [--db URL] [--out FILE.pdf] [--baseline NAME] [--include-closed] [--site "Plant A"] [--site-id N | --all-sites] [--target-sl 1-4] [--no-zones]
```

| Option | Default | Meaning |
|---|---|---|
| `--db` | `$IACS_DATABASE_URL`, else `sqlite:///./iasc_monitor.db` | Database to read. SQLite opens read-only, and a missing file is an error. |
| `--out` | `isa62443_compliance_report.pdf` | Output path |
| `--baseline` | active baseline | Baseline used for attestation scope |
| `--include-closed` | off | Include closed findings |
| `--site` | none | Site name on the cover and footer |
| `--site-id` / `--all-sites` | required when the database has more than one site | One site's data, or a roll-up with one section per site; a multi-site database without either is refused |
| `--target-sl` | every level | Target security level (SL-T 1-4): checks and findings whose 62443-3-3 requirements first apply above it are left out of the findings, severity summary and coverage; the control mapping marks them "> SL-T" |
| `--no-zones` | zones on | Leave out the Zones and Conduits section and the zone SL-T judgement in the findings tables |
| `--layout` | `lrqa` | `lrqa` = the LRQA compliance report (cover, contents, distribution list, engagement particulars, analysis per check, appendix); `public` = the public compliance report (cover table, executive summary, findings by area) |

The report contains (LRQA layout, the default):

- the cover (Prepared For / Project / Author / Date from the Reports page's *Report details*), the
  Contents, 1 Distribution List, 2 Revision History;
- 3 Engagement Particulars: background, scope (firewalls, networks, inputs, target SL - one item per
  line), assessment window / constraints, the finding summary (severity boxes as checks /
  occurrences) and the executive detail (coverage sentence, severity × status, per-area totals,
  remediation priorities);
- 4 Findings: one row per check with the highest severity, the primary reference and the analysis
  section; 5 Analysis: one entry per check on its own page, most severe first (concern, why it is a
  finding, configuration / observed values, affected components, numbered recommendations, FortiOS
  example, further reading);
- 6 Appendix: severity methodology, then the supporting sections (false positives, closed findings,
  checks excluded, attestations, zones and conduits, firewall inventory, shadowed rules, access
  review, check coverage, configuration evidence, control mapping, standards).

The public layout (`--layout public`) keeps the previous structure: cover table, executive summary
(severity × status and per-area totals; the FR × SL matrix is no longer printed), findings grouped by
area and check with the write-ups, then the same supporting sections

**How a finding is judged against a zone SL-T** (Findings page, CSV and PDF; view only - never
stored, never changes a severity). The finding's level is the lowest 62443-3-3 SL of its SRs.
Its device resolves to a zone from the addresses in its evidence (source / destination / host IP)
or, for policy and path findings, from the firewall interfaces or FortiGate zones on each side:
one zone → that zone's SL-T; two zones → the documented conduit's SL-T (else the higher zone SL-T),
or the higher zone SL-T when no conduit is documented; a firewall finding with no address → the
highest SL-T of the documented conduits that firewall carries. The check *applies* when its level
is at or below that SL-T (or it has no 62443-3-3 SR) and is *beyond* otherwise. The owner rule that
no OT device has direct Internet access applies at every SL-T, so the OT-egress checks always apply.

A finding with two ends also carries its **documentation status**: *inside one zone* (both ends in the
same zone - 62443-3-2 covers it by the zone's own requirements), *documented conduit* (a conduit is
documented between the two zones), *no documented conduit* (two zones, nothing documented - the
design gap), *other end in no zone*, or *other end outside the site*. The Findings page shows it on
the zone badge ("· no conduit") and filters on it (Conduit); the CSV has `zone_documentation`; the PDF
marks "in zone" / the conduit name / "no conduit" in the Device column.

**Service-aware lowering (option 3).** A documented conduit can say what it is for: `services`
(a comma list of names such as `s7comm, modbus, enip, rdp, opcua`, or `tcp/102`, `udp/123`, a bare
port, or `any`) and optional `sources` (addresses / CIDRs). A finding on that conduit is **shown one
severity step lower** (critical → high → medium → low) when its service is covered - and, if sources
are set, its source address too. It is computed when the finding is displayed and never stored: the
recorded severity, the summary counts and the sort order are unchanged, the Findings page shows
`high ↓` with the reason, the CSV carries `shown_severity` / `severity_adjustment`, the PDF prints
the shown severity with "recorded …" underneath, and it reverts as soon as the conduit no longer
covers the finding. The OT-egress checks are never lowered. A finding with no port in its evidence
is covered only by `any`.

**Assets in several zones.** IEC 62443-3-2 partitions the system: an asset belongs to exactly one
zone. The page never refuses a second placement (owner decision); it lists *Devices in several zones*
(every address of a MAC resolving to two or more zones) and *Networks in two zones*, resolves a host to
the first zone listed, and the review run raises `host_in_multiple_zones` / `network_in_multiple_zones`
(row 1.2, SR 5.1; medium, high when the zones' SL-T differ). They close when the asset is back in one
zone (`move` on the member relocates every placement).

**Blocked attempts into other zones (SF-5).** `blocked_cross_zone_attempts` (row 8.8, SR 5.1 / 6.2)
reports, per source host, the connection attempts into another zone that were all dropped (no answer
or refused, and no session on that port got through). The segment is the IEC 62443 zone when the site
has zones, else the firewall interface network; Internet targets are left to the egress checks and the
firewall's own addresses are local-in. Each target is marked by its conduit: *no documented conduit*,
*outside the conduit's services*, or - when the documented conduit lists the service and source -
moved to the info finding `conduit_service_blocked` (designed traffic the firewall drops). Severity:
low; medium for management / file-sharing ports, an undocumented path, or a source that is in no
inventory and unclassified; high for such a source on management ports. With no asset inventory,
`unknown_device` also reports an unidentified host (no device type, a level only from the interface
label or a declared subnet) on an L0-L2 network that opened sessions or attempts across the firewall.

**One policy, several conduits (SF-6).** A firewall policy whose side names several interfaces in
different zones (`srcintf port1 port2`) carries several conduits in one rule. It is reported as
`policy_spans_multiple_conduits` (row 3.1, SR 5.1 / 5.2; low, medium when a zone holds L0-L2 assets):
split it per conduit. Finding titles name each interface with its level ("port1 (L1) + port2 (L3)",
evidence `src_zone_parts` / `dst_zone_parts`; Access Review rows likewise), and the zone judgement
treats such a policy as one conduit per zone pair (documented only if every pair is, judged against
the strictest SL-T). An interface that is not itself a zone member resolves to the zone of its network.

**The one check sourced from the zone documentation.** `undocumented_conduit` (row 1.4, SR 5.1;
`app/zone_findings.py`) raises one finding per pair of documented zones that communicate - a
permitting policy or observed traffic - with no documented conduit between them: medium; high when
traffic was observed and a zone holds L0-L2 assets; low when only a policy permits it and nothing was
seen. It closes when the conduit is documented or the path is gone. Pairs with assets in no zone or
the Internet are not findings (the zone page lists them; the egress checks cover the Internet). Together with the multi-zone, policy-span and blocked-attempt checks (all in `app/zone_findings.py`) these are the only checks that read the zone tables.

`GET /reports/compliance.pdf?layout=&baseline=&include_closed=&site=&site_id=&all_sites=&target_sl=&include_zones=` serves the same
PDF, rendered in the threadpool. It returns 404 for an unknown baseline. With several sites the
report covers one site (`site` / `site_id`; the cover shows its name and code and nothing of the
others); `all_sites=true` renders a summary table and one section per site.

---

## Development and testing

```bash
pip install -r requirements-dev.txt        # pytest, pytest-cov, httpx, pypdf, playwright
python -m pytest -q                        # 1414 tests collected
python -m pytest --cov=app --cov-report=term-missing
python -m pytest tests/test_rule_twins.py -q
```

- `tests/conftest.py` points `IACS_DATABASE_URL` at a per-session temporary database, turns off the
  scheduler and moves the scheduler lock, all before `app.db` is imported. The run **fails** if
  `./iasc_monitor.db` is modified.
- **Browser smoke suites** use Playwright. They aren't collected by pytest. Run them against a
  **freshly seeded** throwaway database each time, because they write to it and assert on the seed
  state:

  ```bash
  playwright install chromium                                  # once
  python tests/ui_demo_server.py --db /tmp/ui1.db --port 8765 &
  python tests/ui_smoke_index.py http://127.0.0.1:8765 --shots /tmp/shots_index
  python tests/ui_demo_server.py --db /tmp/ui2.db --port 8766 &
  python tests/ui_smoke_pages.py http://127.0.0.1:8766 --shots /tmp/shots_pages
  ```

  `ui_demo_server.py --no-serve` only seeds the database. The seed plants XSS payloads in untrusted
  fields, and the suites fail if any payload executes. They also check console errors, 4xx/5xx
  responses, counters against the API, and horizontal overflow at phone width.
- **Sample data** is in `sample_data/`:
  - FortiGate, Cisco, pfSense and PAN-OS (XML and set) configs;
  - FortiGate CEF and CSV logs, and ASA, pfSense and PAN-OS syslogs;
  - Cisco and HP switch outputs (running-config, VLAN, CDP, LLDP), MAC tables, and ARP tables
    (Cisco, Unix, Windows);
  - baseline CSVs;
  - two PCAPs: `modbus_sample.pcap`, and `multi_protocol_sample.pcap` (DNP3, S7comm, ENIP/CIP and
    PROFINET DCP).

  Regenerate the PCAPs with `python sample_data/generate_sample_pcap.py`.

---

## Module tree

```
app/
  main.py                 FastAPI app: lifespan (init_db, review scheduler + flock guard), CORS, body-size middleware, /health
  db.py                   Engine/session, SQLite PRAGMAs (FK, WAL, busy_timeout), init_db + Alembic stamping/checks
  models.py               SQLAlchemy models (Host, HostAddressHistory, NetworkSession, ProtocolDetail, Firewall,
                          FirewallDevice, FirewallInterface, FirewallRule, NatRule, FirewallZone, SwitchInterface,
                          SwitchVlan, MacTableEntry, PcapCapture, FortiAnalyzerEvent, Baseline, ApprovedCommsEntry,
                          ApprovedHost, Finding, Attestation, Site + the SiteScoped mixin, SiteDevice,
                          UnmappedLogEvent) and CHECK_TYPE_REFERENCE
  sites.py                Multi-site: resolve_site / get_default_site, ingest_site + @site_ingest binding,
                          flush-time site_id filling (parent site -> ingest site -> Default)
  site_devices.py         Multi-site phase 3: device registry (register / resolve), per-line log routing
                          (LogRouter), unmapped queue, replay, retention purge
  purdue.py               The Purdue level vocabulary (0,1,2,3,3.5,4,5): normalize_level, ordering, predicates
  api/routes.py           Every API route and the UI page routes; upload limits, paging, delete gate
  parsers/
    alert_engine.py         Real-time checks (evaluate_event) and periodic reviews (run_periodic_reviews), dedup/escalation/auto-resolve
    traffic_findings.py     Checklist 8.4: unauthorised industrial write/program operations from PCAP data
    cross_fw_findings.py    Cross-firewall policy-gap checks over confirmed topology links
    forti_config_parser.py  FortiOS show full-configuration: zones, objects, policy/policy6, VIP/ippool NAT, config_* checks
    firewall_parser.py      Cisco IOS/ASA, pfSense, PAN-OS (XML/set) rules and NAT; canonical dst_port
    forti_parser.py         FortiGate/FortiAnalyzer CEF, key=value, CSV report and JSON event ingest (dedup)
    syslog_vendors.py       Cisco ASA/FTD, pfSense/OPNsense filterlog, PAN-OS CSV syslog parsers
    rule_hits.py            FirewallRule.last_matched from traffic log events
    site_scope.py           Per-site analysis scope (analysis_site / @site_scoped loader criteria), CrossSiteError
    pcap_parser.py          PCAP ingest: hosts, sessions, IP defrag, TCP reassembly, analyzer dispatch
    modbus_analyzer.py      Modbus/TCP decoder
    s7comm_analyzer.py      S7comm (TPKT/COTP) decoder
    dnp3_analyzer.py        DNP3 link/transport/application decoder and transport reassembler
    enip_cip_analyzer.py    EtherNet/IP + CIP decoder
    profinet_analyzer.py    PROFINET DCP / RT frame decoder
    smb_analyzer.py         SMBv1 vs SMB2/3 detection
    switch_parser.py        Cisco/HP switch config, VLAN, CDP/LLDP; LLDP role inference
    mac_table_parser.py     MAC address tables; subnet-based VLAN inference
    arp_parser.py           ARP tables (Cisco, Unix, Windows)
    baseline_parser.py      Baseline CSVs (approved comms, approved hosts, asset inventory, reviewed policies)
    inventory_mapping.py    Asset inventory CSV column mapping: suggestions, validation, preview checks
    common.py               Shared host get-or-create/merge, MAC normalisation, vendor lookup
    oui_database.py         Wireshark manuf file loader; MAC kind (universal / locally administered)
    host_identity.py        Host identity across ingests: DHCP renumbering, IP conflicts, history, staleness
    device_classification.py Purdue/device_type classification (manual > protocol > VLAN name > LLDP role > OUI hint > client hint)
    rule_match.py           Shared address/port/range matching primitives
    rule_shadow.py          Rule shadow / duplicate / conflict analysis
    reachability.py         Purdue level reachability matrix and path tracing (multi-FW, NAT-aware)
    topology_diff.py        Observed sessions vs permit rules (unexpected traffic, unused rules)
    topology_manager.py     Multi-firewall link proposals/confirmation, interface labels, Purdue suggestions
ui/                        index.html (console) + upload, findings, topology, fw_topology, attestation pages
alembic/                   env.py, iasc_migration_utils.py, versions/
generate_report.py         Compliance PDF (CLI + used by /reports/compliance.pdf)
generate_audit_report.py   Audit report (PDF + CSV) from the Master Audit Checklist workbook (CLI + used by POST /reports/audit-checklist; app/audit_checklist.py reads the workbook)
tests/                     pytest suite, conftest.py, UI demo server and Playwright smoke suites
sample_data/               Sample configs, logs, PCAPs and baseline CSVs
docs/code-review-remediation.md   Remediation tracker and upgrade notes
install.sh, Dockerfile, docker-compose.yml, docker-entrypoint.sh, build.sh, make-dist.sh
```

---

## Known limitations

These have been verified against the current code.
[`docs/code-review-remediation.md`](docs/code-review-remediation.md) has the full remediation
history (Tier 1–3 fixes, feature items and upgrade notes). Several of its F- and N- rows are still
marked *Open* even though the code now implements them (for example auto-resolve, NAT, L3.5, delete
endpoints, multi-vendor syslog and `/findings?q=`). Where the two disagree, this section reflects the
code.

1. **No authentication or authorisation.** The project owner decided this. Anyone who can reach the
   port can read every finding and upload data. Delete endpoints are off unless
   `IACS_ENABLE_DELETE=true`. Bind to `127.0.0.1` (the `install.sh` default) or a trusted
   management network, or put the service behind an authenticating reverse proxy. **Plan
   authentication before exposing the service beyond a trusted network.**
2. **SQLite legacy databases** (tracker N-07, *Known limitation*): the reconcile revision can't
   create foreign keys on columns it adds, because SQLite can't add FK constraints that way. The
   PostgreSQL migration path has only been checked by rendering it offline (`--sql`), not by running
   it against a server.
3. **PostgreSQL timestamps written before the UTC fix** (tracker N-18, *Known limitation*) may be
   offset by the server's TimeZone. They can't be corrected automatically.
4. **Docker image build** (tracker N-19, *Open*): the build hasn't been verified end to end in the
   development environment. Run `docker build` once on your platform. Also note that `build.sh`'s
   default `PYTHON_VERSION=3.11` bypasses the Dockerfile's patch pin; see above.
5. **The scheduler guard is per host.** The flock prevents duplicate runs across workers on one
   machine, but several hosts sharing one PostgreSQL database would each run the scheduled reviews.
   `/diagnostics` counters are also per process.
6. **FortiOS multi-VDOM:** VDOMs are flattened. Objects or policies with the same name in two VDOMs
   collide (the last one wins), and a warning with the collision count is logged.
7. **Analysis scope:**
   - Reachability level-pair queries are NAT-agnostic (host queries apply NAT), and intra-level
     traffic isn't modelled.
   - **What shapes the path model** (MP-20): interface Purdue labels define a firewall's legs and so
     its enforcement points; the upload boundary stands in only while a firewall has no labels. A
     paired group, a confirmed upstream chain (`topology_confirmed`) and a confirmed inside↔outside
     link put two boxes in series; a link whose ends sit at the same level is a shared segment
     (parallel). Other confirmed links and segments drive the cross-firewall comparisons, the level
     suggestions and the topology page, not the path model. A capture's router MAC (carrier) selects
     between alternative boxes.
   - Several firewalls on one level pair are **alternatives** (one permitting path is enough) unless
     they are declared in series — a paired firewall group, a confirmed upstream chain, or a confirmed
     inside↔outside link — in which case every box must permit. For a host query only the boxes whose
     labelled interface networks hold the flow's addresses (or the carrier seen in a capture) decide;
     the others are shown "not on path". Declare the relation when two boxes really sit one behind
     the other, or the engine will treat them as parallel. A paired group's members must sit on one
     level pair (label the transit link as the far side on each member); a group whose members are
     mislabelled, unplaced or unlinked is reported as `paired_group_warnings` (docs/firewall-groups.md).
   - A firewall whose interfaces carry no Purdue level (and no boundary) is **not in the model**: it
     is listed as `unplaced_firewalls` (Reachability / Access Review banners, report) and nothing is
     evaluated through it. A single interface without a level on an otherwise labelled firewall is
     "another leg": rules on it are not judged on any crossing (listed per enforcement point as
     "not judged here"), so label every routed interface. A firewall with an upload boundary and no
     labels at all has its rules read from the boundary, both ways, with rule findings one severity
     step lower and marked "direction unverified". When the upload boundary and the interface labels
     disagree, the labels decide (a boundary level between labelled legs is ignored, one beyond them
     is taken as the unlabelled far leg) and the disagreement is reported as `label_conflicts`.
     Where levels have hosts but no firewall between them, an unfirewalled hop is inferred and
     printed in the path (`~ L2 (inferred, no firewall)`); while a firewall is unplaced, any verdict
     over such a hop is `unknown`.
   - A row's source scope is placed by the labelled interface network that holds it (a network is
     placed like a host), so an upstream `10.4.0.0/24` never appears as an L3 or DMZ source. A row
     whose destination lives beyond the level it reaches is marked `reach: prefix` (a longer row
     carries it) or `dead_end` (the dead_end_permit finding names the blocking firewall, tracing a
     network scope through one of its addresses); such rows keep only level-independent flags and
     are left out of the report by default. Specific denies in front of a permit-any (deny tcp/502,
     permit any) are subtracted on every path that crosses the firewall.
   - `chain_it_ot_bypass` severity follows the source band (internet > enterprise > DMZ / site
     operations) and the destination band (L0/L1 > L2); the finding names the narrowest policy of the
     chain as the change point, and VPN-sourced policies are judged by `vpn_direct_to_ot` alone (the
     protocol checks still see them). A host path lookup evaluates every level path and reports the
     most permissive one with the others listed (`alternatives`); two hosts on two legs of one
     firewall at the same level are evaluated against that firewall's policies. Composed conduits
     run to three legs through single-host pivots; leg pairs that meet on a network are listed as
     `composition_notes`.
   - A policy whose destination is an address group of N hosts is N permitted-path rows (one per
     member, each with its own traffic overlay, tag and finding evidence). The Access Review screen
     and the report's permitted-path tables roll rows that differ only in the destination (or
     source) host into one line; the counts stay per row.
   - The permitted-path list has a row budget (`IACS_MAX_ACCESS_PATH_ROWS`, default 20000). Level
     pairs are enumerated IT → OT first, deepest first, so a truncated list loses those rows last;
     a truncated run raises an informational `access_path_enumeration_truncated` finding and the
     chain reviews' findings are not auto-resolved. `GET /reviews/rules-not-judged` (also on Reports
     & Diagnostics and in the report) lists the permit policies the rule-level reviews could not
     judge because a side resolves to no Purdue level.
   - A named address object that wasn't expanded makes a device "unknown" when it could change the
     outcome.
   - `/diff` evaluates only the first 10,000 sessions (`sessions_truncated` is reported) and ignores
     MAC-only PROFINET sessions. "Unused" means unused in the ingested data.
   - Shadow analysis doesn't expand zone membership, so a zone versus a member interface counts as
     disjoint (false negatives only).
8. **Protocol decoding:**
   - EtherNet/IP Class 1 implicit I/O (UDP 2222) and PROFINET acyclic DCE/RPC (UDP 34964) aren't
     decoded.
   - DNP3 CRCs aren't validated.
   - Parts of the S7comm, CIP and PROFINET decoding are lower confidence. Each analyzer's module
     docstring says which parts.
   - The PCAP parser doesn't capture live traffic; it only ingests files.
9. **`config_ntp_fortiguard`** judges FortiGuard and custom servers; a hostname other than a pool / public name
   is classed external because it cannot be resolved offline.
10. **Multi-site** (see [Sites](#sites-multi-site)):
   - Stored events and findings are not moved when a device is remapped or a site is renamed
     (remap affects new log lines only).
   - Held lines of unmapped devices (`unmapped_pending`) and held conflicts (`conflicts_pending`)
     belong to no site, so those counts are global.
   - Uploaded log files carry no transport source IP, so devices cannot be pinned by source IP:
     two name-only devices (no serial) with the same name at two sites cannot be told apart.
   - The roll-up's `last_review_at` is per server process (empty after a restart).
   - The roll-up and the all-sites PDF are aggregation only; there are no cross-site analyses.
   - Config exports normally carry no serial, so auto-registration is by hostname; add serials with
     `PATCH /site-devices/{id}` when two sites use the same device name.
