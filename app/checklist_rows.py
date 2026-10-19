"""IEC 62443 workbook rows (OT_Firewall_Review_62443_Checklist.xlsx, sheet "Checklist"):
id -> title, section, 62443 reference, NIST reference and "How to verify".
Generated from the workbook; used by app.explain."""

ROWS = {
 "1.1": {
  "title": "Zone and conduit diagrams are current and each zone has an assigned target SL",
  "section": "1. Documentation & Scoping",
  "ref_62443": "3-2 ZCR 3, ZCR 5; 2-1 NET 1.2",
  "nist": "PL-8, CA-9, RA-3",
  "verify": "Request diagrams. Reconstruct zones from config system interface / zone / VLANs and compare."
 },
 "1.2": {
  "title": "Asset inventory and IP plan exist per zone",
  "section": "1. Documentation & Scoping",
  "ref_62443": "3-3 SR 7.8; 2-1 SPE 2 (CM)",
  "nist": "CM-8",
  "verify": "Request inventory. Validate against ARP table and hosts seen in PCAP."
 },
 "1.3": {
  "title": "Required communications documented per conduit (source, destination, protocol, direction, justification)",
  "section": "1. Documentation & Scoping",
  "ref_62443": "3-2 ZCR 3; 2-1 NET 1.2",
  "nist": "CA-3, CA-9, AC-4",
  "verify": "Request communications matrix. Needed to judge whether policies and observed flows are legitimate."
 },
 "1.4": {
  "title": "Config export is current and matches the running configuration",
  "section": "1. Documentation & Scoping",
  "ref_62443": "3-3 SR 7.6; 2-1 SPE 2 (CM)",
  "nist": "CM-2, CM-6",
  "verify": "Check #config-version header and backup date; confirm with client that it was exported from the running unit/VDOM."
 },
 "1.5": {
  "title": "Passive-only data collection agreed (SPAN/TAP, no active scanning of live control networks)",
  "section": "1. Documentation & Scoping",
  "ref_62443": "Rules of engagement",
  "nist": "800-82r3 passive monitoring guidance; SI-4",
  "verify": "Confirm in scope/RoE document before capture."
 },
 "2.1": {
  "title": "No direct IT to Level 1/2 path; all IT-OT traffic terminates in a DMZ",
  "section": "2. Zone & Conduit Architecture",
  "ref_62443": "3-3 SR 5.1 RE2; 2-1 NET 1.1",
  "nist": "SC-7, SC-7(21), AC-4",
  "verify": "Policies with IT srcintf and OT dstintf; confirm no such flows in PCAP."
 },
 "2.2": {
  "title": "No flow bridges the DMZ end-to-end (IT to DMZ to OT without a broker/proxy)",
  "section": "2. Zone & Conduit Architecture",
  "ref_62443": "3-3 SR 5.2",
  "nist": "SC-7, SC-7(8), AC-4",
  "verify": "Compare IT-to-DMZ and DMZ-to-OT policies for the same service/host pairs; check PCAP for pass-through sessions."
 },
 "2.3": {
  "title": "SIS zone isolated, with conduits to BPCS restricted to the minimum required",
  "section": "2. Zone & Conduit Architecture",
  "ref_62443": "2-1 NET 1.3; 3-3 SR 5.1 RE3",
  "nist": "SC-7(21), AC-4(21)",
  "verify": "Policies touching SIS interface/address objects; observed SIS traffic in PCAP."
 },
 "2.4": {
  "title": "Internal segmentation between OT zones, not only at the perimeter",
  "section": "2. Zone & Conduit Architecture",
  "ref_62443": "3-3 SR 5.1; 2-1 NET 1.6",
  "nist": "SC-7(21), AC-4",
  "verify": "Policies between OT interfaces; flag OT subnets sharing one flat interface/VLAN."
 },
 "2.5": {
  "title": "Wireless networks are a separate zone behind the firewall",
  "section": "2. Zone & Conduit Architecture",
  "ref_62443": "2-1 NET 2.2; 3-3 SR 1.6",
  "nist": "AC-18, SC-7",
  "verify": "Wi-Fi/SSID interfaces and policies sourced from them."
 },
 "2.6": {
  "title": "No dual-homed hosts bypassing the firewall",
  "section": "2. Zone & Conduit Architecture",
  "ref_62443": "3-3 SR 5.1",
  "nist": "SC-7, CM-8",
  "verify": "ARP: same MAC with IPs on different interfaces. PCAP: same MAC seen on different segments."
 },
 "2.7": {
  "title": "No devices in the wrong zone",
  "section": "2. Zone & Conduit Architecture",
  "ref_62443": "3-3 SR 5.1; SR 7.8",
  "nist": "CM-8, SC-7",
  "verify": "MAC OUI vendor lookup on ARP entries (e.g., PLC vendor OUI on an IT VLAN)."
 },
 "2.8": {
  "title": "Conduit controls meet the target SL of the zones they connect",
  "section": "2. Zone & Conduit Architecture",
  "ref_62443": "3-2 ZCR 5; 3-3 FR 5",
  "nist": "RA-3, PL-8",
  "verify": "Needs target SLs from client; compare policy/UTM controls against 3-3 SR/RE requirements for that SL."
 },
 "3.1": {
  "title": "Default deny with explicit allow rules only",
  "section": "3. Ruleset Review",
  "ref_62443": "3-3 SR 5.2 RE1",
  "nist": "SC-7(5), AU-12",
  "verify": "No catch-all accept above implicit deny; config log setting > fwpolicy-implicit-log enable."
 },
 "3.2": {
  "title": "No any/any rules; no 'all' in source, destination or service without justification",
  "section": "3. Ruleset Review",
  "ref_62443": "3-3 SR 5.2; SR 7.7",
  "nist": "SC-7(5), CM-7",
  "verify": "srcaddr \"all\", dstaddr \"all\", service \"ALL\" in config firewall policy."
 },
 "3.3": {
  "title": "No overly broad subnets or port ranges where specific hosts/ports are known",
  "section": "3. Ruleset Review",
  "ref_62443": "3-3 SR 5.2; 2-1 NET 1.7",
  "nist": "SC-7(11), CM-7",
  "verify": "Large address/addrgrp objects and custom service ranges; compare to hosts/ports actually used in PCAP."
 },
 "3.4": {
  "title": "Rules are directional and match the documented initiator",
  "section": "3. Ruleset Review",
  "ref_62443": "3-3 SR 5.2",
  "nist": "SC-7(11), AC-4",
  "verify": "srcintf/dstintf vs. which host sends the TCP SYN in PCAP."
 },
 "3.5": {
  "title": "Insecure services blocked or justified (Telnet, FTP, HTTP, SMBv1, SNMPv1/v2c, TFTP)",
  "section": "3. Ruleset Review",
  "ref_62443": "3-3 SR 7.7, SR 4.1; 2-1 NET 1.7",
  "nist": "CM-7, SC-8",
  "verify": "Services in policies; confirm actual use in PCAP."
 },
 "3.6": {
  "title": "Email, web browsing and chat blocked into/from control zones",
  "section": "3. Ruleset Review",
  "ref_62443": "3-3 SR 5.3; 2-1 NET 1.8",
  "nist": "SC-7, CM-7",
  "verify": "Policies allowing 25/80/443/messaging from OT; observed traffic."
 },
 "3.7": {
  "title": "Internet egress from OT zones blocked or restricted to a DMZ proxy",
  "section": "3. Ruleset Review",
  "ref_62443": "3-3 SR 5.1 RE2",
  "nist": "SC-7(5), SC-7(8)",
  "verify": "Policies from OT interfaces to WAN; public DNS/NTP/cloud/update traffic in PCAP."
 },
 "3.8": {
  "title": "Unused rules identified for removal",
  "section": "3. Ruleset Review",
  "ref_62443": "3-3 SR 7.7; 2-1 SPE 2 (CM)",
  "nist": "CM-7(1), SC-7(4)",
  "verify": "Config backup has no hit counts. Request hit counts/last-used (GUI or FortiAnalyzer); PCAP is supporting evidence only."
 },
 "3.9": {
  "title": "Shadowed, redundant and conflicting rules identified",
  "section": "3. Ruleset Review",
  "ref_62443": "3-3 SR 7.6",
  "nist": "CM-6",
  "verify": "Policy order analysis (manual or FortiManager policy check)."
 },
 "3.10": {
  "title": "Every rule has a description, owner and change ticket reference",
  "section": "3. Ruleset Review",
  "ref_62443": "2-1 SPE 2 (CM)",
  "nist": "CM-3",
  "verify": "set comments on each policy; ticket traceability needs change records."
 },
 "3.11": {
  "title": "Temporary rules have expiry dates and none are expired but still active",
  "section": "3. Ruleset Review",
  "ref_62443": "2-1 SPE 2 (CM)",
  "nist": "CM-3, SC-7(4)",
  "verify": "config firewall schedule onetime with past end dates still attached to policies."
 },
 "3.12": {
  "title": "Industrial protocol DPI used where available (e.g., read-only Modbus, block unauthorized S7/CIP downloads)",
  "section": "3. Ruleset Review",
  "ref_62443": "3-3 SR 5.2, SR 3.5",
  "nist": "SC-7, SI-4, SI-10",
  "verify": "set utm-status enable; ips-sensor / application-list with OT/ICS signatures on OT policies."
 },
 "3.13": {
  "title": "Anti-spoofing / ingress-egress filtering enabled",
  "section": "3. Ruleset Review",
  "ref_62443": "3-3 SR 5.2",
  "nist": "SC-7",
  "verify": "src-check on interfaces (default enabled); asymroute not enabled in config system settings."
 },
 "4.1": {
  "title": "All remote access terminates in the DMZ (jump host), never directly into control zones",
  "section": "4. Remote Access",
  "ref_62443": "2-1 NET 3.2; 3-3 SR 1.13",
  "nist": "AC-17(3), MA-4",
  "verify": "Policies from SSL VPN / IPsec interfaces: destinations should be jump hosts only."
 },
 "4.2": {
  "title": "MFA required for remote access",
  "section": "4. Remote Access",
  "ref_62443": "3-3 SR 1.1 RE2/RE3, SR 1.13 RE1",
  "nist": "IA-2(1), IA-2(2), AC-17",
  "verify": "two-factor on config user local, or RADIUS/SAML/FortiToken auth on VPN user groups."
 },
 "4.3": {
  "title": "Vendor access disabled by default and enabled on request, time-limited",
  "section": "4. Remote Access",
  "ref_62443": "2-1 NET 3.2, NET 3.3; 3-3 SR 1.13 RE1",
  "nist": "AC-17, AC-2, MA-4",
  "verify": "Schedules on vendor policies, disabled vendor accounts; process confirmed by interview."
 },
 "4.4": {
  "title": "Remote session timeout and termination configured",
  "section": "4. Remote Access",
  "ref_62443": "3-3 SR 2.6; 2-1 NET 3.3",
  "nist": "AC-12, SC-10",
  "verify": "config vpn ssl settings > idle-timeout, auth-timeout; IPsec phase1 settings."
 },
 "4.5": {
  "title": "Remote access applications are approved; no unapproved remote support tools",
  "section": "4. Remote Access",
  "ref_62443": "2-1 NET 3.1",
  "nist": "AC-17, CM-7",
  "verify": "PCAP: TeamViewer, AnyDesk, RDP/VNC not sourced from jump host. Config: application control blocking remote access apps."
 },
 "4.6": {
  "title": "Remote sessions logged (and recorded where required)",
  "section": "4. Remote Access",
  "ref_62443": "3-3 SR 2.8",
  "nist": "AC-17(1), AU-2",
  "verify": "logtraffic on VPN policies; session recording is on the jump host (request evidence)."
 },
 "5.1": {
  "title": "Management access restricted to a dedicated management zone",
  "section": "5. Firewall Hardening & Management",
  "ref_62443": "3-3 SR 5.1; 4-2 NDR 5.2",
  "nist": "AC-3, SC-7",
  "verify": "allowaccess per interface (none on OT/WAN), trusthost on admins, config firewall local-in-policy."
 },
 "5.2": {
  "title": "Encrypted management protocols only (SSH, HTTPS, SNMPv3)",
  "section": "5. Firewall Hardening & Management",
  "ref_62443": "3-3 SR 4.1, SR 3.1",
  "nist": "SC-8, SC-13",
  "verify": "No telnet/http in allowaccess; strong-crypto enable; config system snmp user (v3) not community (v1/v2c)."
 },
 "5.3": {
  "title": "Individual admin accounts with role-based access and MFA",
  "section": "5. Firewall Hardening & Management",
  "ref_62443": "3-3 SR 1.1, SR 1.3, SR 2.1",
  "nist": "AC-2, AC-6, IA-2(1)",
  "verify": "config system admin: named accounts, accprofile, two-factor."
 },
 "5.4": {
  "title": "Default credentials changed and password policy enforced",
  "section": "5. Firewall Hardening & Management",
  "ref_62443": "3-3 SR 1.5, SR 1.7",
  "nist": "IA-5(1)",
  "verify": "config system password-policy; no default 'admin' account in use."
 },
 "5.5": {
  "title": "Account lockout, admin timeout and login banner configured",
  "section": "5. Firewall Hardening & Management",
  "ref_62443": "3-3 SR 1.11, SR 1.12",
  "nist": "AC-7, AC-8, AC-12",
  "verify": "config system global > admin-lockout-threshold, admin-lockout-duration, admintimeout, pre-login-banner."
 },
 "5.6": {
  "title": "Firmware on a supported version with known CVEs assessed",
  "section": "5. Firewall Hardening & Management",
  "ref_62443": "2-1 SPE 4 (COMP); 4-2",
  "nist": "SI-2, RA-5",
  "verify": "Version in config header; check against Fortinet PSIRT advisories."
 },
 "5.7": {
  "title": "Unused interfaces and firewall services disabled",
  "section": "5. Firewall Hardening & Management",
  "ref_62443": "3-3 SR 7.7",
  "nist": "CM-7",
  "verify": "Interface status down when unused; minimal allowaccess; unneeded features disabled."
 },
 "5.8": {
  "title": "Management-plane traffic to the firewall only from authorized hosts",
  "section": "5. Firewall Hardening & Management",
  "ref_62443": "3-3 SR 5.1, SR 2.1",
  "nist": "AC-3, SI-4",
  "verify": "HTTPS/SSH/SNMP to firewall IPs from non-management hosts in PCAP."
 },
 "5.9": {
  "title": "Configuration backups taken regularly, stored securely, restores tested",
  "section": "5. Firewall Hardening & Management",
  "ref_62443": "3-3 SR 7.3; 2-1 SPE 2 (CM)",
  "nist": "CP-9, CP-10",
  "verify": "Automation/backup settings or FortiManager; request backup and restore-test records."
 },
 "6.1": {
  "title": "Traffic logging enabled on conduit policies",
  "section": "6. Logging & Monitoring",
  "ref_62443": "3-3 SR 2.8",
  "nist": "AU-2, AU-12",
  "verify": "set logtraffic all (or utm) on each conduit policy."
 },
 "6.2": {
  "title": "Admin logins and configuration changes logged",
  "section": "6. Logging & Monitoring",
  "ref_62443": "3-3 SR 2.8, SR 2.12",
  "nist": "AU-2, AU-12",
  "verify": "config log eventfilter: system/event logging enabled."
 },
 "6.3": {
  "title": "Logs forwarded to SIEM/log server with adequate retention",
  "section": "6. Logging & Monitoring",
  "ref_62443": "3-3 SR 6.1, SR 2.9",
  "nist": "AU-4, AU-9(2), AU-11",
  "verify": "config log syslogd setting / fortianalyzer setting; syslog/OFTP in PCAP; retention confirmed with client."
 },
 "6.4": {
  "title": "NTP from a trusted internal source; consistent timestamps",
  "section": "6. Logging & Monitoring",
  "ref_62443": "3-3 SR 2.11; 2-1 NET 1.9",
  "nist": "AU-8, SC-45",
  "verify": "config system ntp; observed NTP destinations in PCAP."
 },
 "6.5": {
  "title": "Alerting for key events (config change, deny-all hits, admin login failure)",
  "section": "6. Logging & Monitoring",
  "ref_62443": "3-3 SR 6.2",
  "nist": "SI-4(5), AU-6",
  "verify": "Automation stitches on FortiGate; SIEM use cases need client evidence."
 },
 "7.1": {
  "title": "Fail-close behavior confirmed and appropriate to process risk",
  "section": "7. Availability & Resilience",
  "ref_62443": "3-3 SR 5.2 RE3",
  "nist": "SC-7(18), SC-24",
  "verify": "config ips global > fail-open (flag if enabled); bypass behavior is model-specific and needs documentation or test."
 },
 "7.2": {
  "title": "Island mode (rapid disconnect of external conduits) capability documented",
  "section": "7. Availability & Resilience",
  "ref_62443": "3-3 SR 5.2 RE2; 2-1 NET 1.5",
  "nist": "IR-4, SC-7",
  "verify": "Request procedure; confirm with interview or tabletop."
 },
 "7.3": {
  "title": "OT can operate autonomously if IT/external links are lost",
  "section": "7. Availability & Resilience",
  "ref_62443": "2-1 NET 1.4",
  "nist": "SC-7; 800-82r3 OT/IT separation",
  "verify": "PCAP: OT dependencies on IT services (AD, DNS, licensing, file shares). Confirm with interview."
 },
 "7.4": {
  "title": "HA/failover configured and tested where required",
  "section": "7. Availability & Resilience",
  "ref_62443": "3-3 SR 7.1, SR 7.2",
  "nist": "CP-10",
  "verify": "config system ha; request failover test records."
 },
 "7.5": {
  "title": "DoS protections configured without impacting control traffic",
  "section": "7. Availability & Resilience",
  "ref_62443": "3-3 SR 7.1",
  "nist": "SC-5",
  "verify": "config firewall DoS-policy on OT-facing interfaces; thresholds reviewed against normal traffic."
 },
 "8.1": {
  "title": "Flow matrix built from PCAP matches documented required communications",
  "section": "8. PCAP / ARP Validation",
  "ref_62443": "3-2 ZCR 3; 2-1 NET 1.2",
  "nist": "CA-9, AC-4, SI-4",
  "verify": "Extract conversations (src, dst, proto, port); compare with communications matrix and policies."
 },
 "8.2": {
  "title": "Cross-zone flows with no documented requirement identified",
  "section": "8. PCAP / ARP Validation",
  "ref_62443": "3-3 SR 5.2",
  "nist": "AC-4, SI-4(4)",
  "verify": "Flows in PCAP that match a permissive policy but have no justification."
 },
 "8.3": {
  "title": "Cleartext credentials in traffic",
  "section": "8. PCAP / ARP Validation",
  "ref_62443": "3-3 SR 4.1, SR 3.1",
  "nist": "IA-5(1), SC-8",
  "verify": "Telnet, FTP, HTTP basic auth, SNMP community strings in PCAP."
 },
 "8.4": {
  "title": "Industrial write/program operations only from authorized hosts",
  "section": "8. PCAP / ARP Validation",
  "ref_62443": "3-3 SR 2.1, SR 3.5",
  "nist": "AC-3, SI-10, SI-4",
  "verify": "Modbus FC 5/6/15/16, S7 download, CIP writes, DNP3 control from unexpected sources."
 },
 "8.5": {
  "title": "No broadcast/multicast leakage between zones",
  "section": "8. PCAP / ARP Validation",
  "ref_62443": "3-3 SR 5.1, SR 7.7",
  "nist": "SC-7, CM-7",
  "verify": "LLMNR, NetBIOS, SSDP, mDNS crossing zones in PCAP."
 },
 "8.6": {
  "title": "Unknown devices not in the asset inventory",
  "section": "8. PCAP / ARP Validation",
  "ref_62443": "3-3 SR 7.8",
  "nist": "CM-8(3)",
  "verify": "Compare ARP and PCAP MAC/IP list with inventory."
 },
 "8.7": {
  "title": "IP conflicts / duplicate addresses",
  "section": "8. PCAP / ARP Validation",
  "ref_62443": "3-3 SR 7.8",
  "nist": "CM-8",
  "verify": "Multiple MACs for one IP in ARP or gratuitous ARP in PCAP."
 },
 "8.8": {
  "title": "Scanning or anomalous traffic volumes",
  "section": "8. PCAP / ARP Validation",
  "ref_62443": "3-3 SR 6.2, SR 7.1",
  "nist": "SI-4(4), SI-4",
  "verify": "Port/host sweeps, unusual volumes compared with the baseline across the capture window."
 },
 "9.1": {
  "title": "Split tunneling disabled on remote access used for OT",
  "section": "9. NIST / CIS Additions",
  "ref_62443": "3-3 SR 1.13, SR 5.1; 2-1 NET 3.2",
  "nist": "SC-7(7), AC-17",
  "verify": "SSL VPN portals and IPsec dial-up mode-config used by OT/vendor users must not allow split tunnels."
 },
 "9.2": {
  "title": "OT does not depend on the corporate (IT) Active Directory",
  "section": "9. NIST / CIS Additions",
  "ref_62443": "3-3 SR 5.1 RE2, SR 1.1; 2-1 NET 1.4",
  "nist": "800-82r3 separate OT domain; AC-2, IA-2",
  "verify": "OT authentication should use an OT-side domain or local accounts, with no trust to IT AD."
 },
 "9.3": {
  "title": "Unidirectional gateway (data diode) considered for highest-SL zones",
  "section": "9. NIST / CIS Additions",
  "ref_62443": "3-3 SR 5.1 RE3, SR 5.2; 3-2 ZCR 5",
  "nist": "AC-4(21), SC-7; 800-82r3 architecture",
  "verify": "For zones at SL-T 3/4 (e.g. SIS, critical control), check whether outbound data flows could be one-way only."
 },
 "9.4": {
  "title": "Admin authentication centralized (RADIUS/TACACS+), local break-glass account only, auth server in OT/management zone",
  "section": "9. NIST / CIS Additions",
  "ref_62443": "3-3 SR 1.1, SR 1.3 RE1; 2-1 SPE 6 (USER)",
  "nist": "IA-2, AC-2(1)",
  "verify": "Admins should authenticate against a central server; one documented local emergency account."
 },
 "9.5": {
  "title": "Admin access only from dedicated admin workstations",
  "section": "9. NIST / CIS Additions",
  "ref_62443": "3-3 SR 5.1, SR 2.1; 2-1 SPE 6 (USER)",
  "nist": "SC-7(15), AC-6",
  "verify": "Trusted hosts should be specific admin workstations, not whole subnets. See also 5.1 and 5.8."
 },
 "9.6": {
  "title": "USB auto-install of configuration and firmware disabled",
  "section": "9. NIST / CIS Additions",
  "ref_62443": "3-3 SR 2.3, SR 3.4; 4-2 NDR 2.13",
  "nist": "SC-41, CM-7",
  "verify": "Prevents config or firmware being loaded from a USB stick at boot."
 },
 "9.7": {
  "title": "Maintainer account disabled (or risk accepted with physical controls)",
  "section": "9. NIST / CIS Additions",
  "ref_62443": "3-3 SR 1.1, SR 1.3; 2-1 SPE 6 (USER)",
  "nist": "AC-2, CM-7",
  "verify": "Maintainer allows password reset from the console; acceptable only with strong physical security."
 },
 "9.8": {
  "title": "Static-key TLS ciphers disabled",
  "section": "9. NIST / CIS Additions",
  "ref_62443": "3-3 SR 4.3, SR 3.1",
  "nist": "SC-13, SC-8",
  "verify": "Only forward-secret cipher suites for admin HTTPS and SSL VPN."
 },
 "9.9": {
  "title": "HA heartbeat authenticated and encrypted",
  "section": "9. NIST / CIS Additions",
  "ref_62443": "3-3 SR 3.1, SR 4.1",
  "nist": "SC-8",
  "verify": "Applies only where HA is used."
 },
 "9.10": {
  "title": "Log transport to FortiAnalyzer / syslog encrypted and reliable",
  "section": "9. NIST / CIS Additions",
  "ref_62443": "3-3 SR 2.8, SR 3.9, SR 3.1",
  "nist": "AU-9, SC-8",
  "verify": "Protects log integrity in transit."
 },
 "9.11": {
  "title": "Firewall DNS points to internal resolvers, not public or FortiGuard DNS",
  "section": "9. NIST / CIS Additions",
  "ref_62443": "3-3 SR 5.1 RE2, SR 7.6; 2-1 NET 1.4",
  "nist": "SC-7, SC-20, SC-21",
  "verify": "Default FortiOS DNS is FortiGuard; in OT it should be internal."
 },
 "9.12": {
  "title": "Signature and firmware updates from FortiManager or an internal source, not directly from the internet",
  "section": "9. NIST / CIS Additions",
  "ref_62443": "3-3 SR 5.1 RE2, SR 3.4; 2-1 SPE 4 (COMP)",
  "nist": "SI-2, SC-7",
  "verify": "Confirm how IPS/OT signatures reach the firewall and that they are current."
 },
 "9.13": {
  "title": "Hostname and timezone set (log correlation)",
  "section": "9. NIST / CIS Additions",
  "ref_62443": "3-3 SR 2.11; 2-1 NET 1.9",
  "nist": "AU-8",
  "verify": "Minor, but supports incident investigation across devices."
 },
 "9.14": {
  "title": "Periodic firewall ruleset review defined and evidenced",
  "section": "9. NIST / CIS Additions",
  "ref_62443": "2-1 SPE 2 (CM), NET 1.2; 3-3 SR 7.6",
  "nist": "SC-7(4), CM-7(1)",
  "verify": "Request the review procedure and the last review record; compare with last-used dates (3.8)."
 }
}

# Row titles as the app's checks state them (Finding.detail["checklist_title"]).
# Where they differ from ROWS the app's check was mapped against another
# edition of the workbook; app.explain shows both (``mismatch``).
APP_TITLES = {
 "1.1": "OT zones are formally defined and documented",
 "1.2": "Zones are defined by risk/consequence",
 "1.3": "Zone boundaries are enforced by controls (FW/VLAN)",
 "1.4": "Communication conduits between zones are documented",
 "1.5": "Security requirements are defined per zone",
 "1.6": "Zone documentation has been reviewed and approved",
 "2.1": "No direct IT to Level 1/2 path",
 "2.2": "No flow bridges the DMZ end-to-end",
 "2.3": "Historian server placed in Site Operations zone (Level 3), not in",
 "2.5": "All management access to OT equipment restricted to a dedicated",
 "2.6": "No wireless access points found in OT/control zones",
 "2.7": "No devices in the wrong zone (OT equipment in IT zone)",
 "3.1": "Default deny with explicit allow rules only",
 "3.5": "Insecure services blocked or justified",
 "3.7": "Internet egress from OT zones blocked",
 "3.8": "Unused rules identified for removal",
 "3.9": "Shadowed, redundant and conflicting rules identified",
 "3.10": "Policy references only concrete, resolvable address objects —",
 "3.12": "Industrial protocol DPI used where available",
 "4.1": "All remote access terminates in the DMZ (jump host)",
 "4.5": "Remote access applications are approved",
 "5.1": "Management access restricted to zone - only from approved management",
 "6.2": "Admin logins and configuration changes logged",
 "6.3": "Logs forwarded to SIEM/log server with adequate retention",
 "6.4": "NTP from a trusted internal source; consistent timestamps",
 "7.1": "Critical connections have redundant paths",
 "7.2": "Redundant paths verified by test or continuous monitoring",
 "7.3": "OT can operate autonomously if IT/external links are lost",
 "7.4": "HA/failover configured and tested where required",
 "7.7": "Asset inventory complete: all discovered devices match the documented",
 "7.8": "OT device firmware versions are documented and current",
 "8.1": "Flow matrix built from PCAP matches documented required comms",
 "8.2": "Cross-zone flows with no documented requirement identified",
 "8.3": "Cleartext credentials not transmitted in the clear",
 "8.4": "Industrial write/program operations only from authorized hosts",
 "8.6": "All devices accounted for in asset inventory",
 "8.7": "IP conflicts / duplicate addresses",
 "8.8": "Scanning or anomalous traffic volumes",
 "9.2": "OT does not depend on the corporate (IT) Active Directory",
 "9.3": "OT devices sync NTP from a dedicated internal NTP server, not",
 "9.11": "Firewall DNS points to internal resolvers",
 "9.12": "Signature/firmware updates from internal source"
}
