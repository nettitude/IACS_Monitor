"""
"Why this was flagged" - the explanation of a finding (UI finding panel,
GET /findings/{id}/explanation, PDF report).

explain(finding) returns:

    {"check", "title",
     "what":        {"text": the finding's own description (or one built from
                     its fields), "facts": [[label, value]], "path": {...} | None},
     "why":         why the condition is a risk (plain language, per check),
     "requirement": {"sr", "rows": [{id, title, section, ref_62443, nist}]},
     "severity":    {"level", "default", "reason"},
     "resolve":     what to change,
     "close":       how the finding closes (or is accepted),
     "verify":      how to confirm it by hand (workbook "How to verify"),
     "evidence":    the remaining raw fields (for the collapsed view)}

The per-check text lives in CATALOGUE (one entry per check_name: why, fix,
optional close).  Checks without an entry fall back to their family (prefix)
text, so every finding gets an explanation.  The severity reason is the
finding's own ``severity_reason`` when the check recorded one, else it is
derived from the default severity and the evidence.
"""
from __future__ import annotations

from typing import Optional

from app.checklist_rows import APP_TITLES, ROWS

# ----------------------------------------------------------------- catalogue
# why: the risk in plain language.  fix: what to change.  close: (optional)
# how this finding closes, when it differs from its category's default.
C = {}


def _e(names, why, fix, close=None):
    for n in names.split():
        C[n] = {"why": why, "fix": fix, **({"close": close} if close else {})}


# --- IT/OT boundary, paths, DMZ ---------------------------------------------
_e("it_ot_bypass session_it_ot_bypass rule_it_ot_bypass chain_it_ot_bypass intervlan_routing_unchecked",
   "Traffic from the IT side reaches basic control (L0/L1), or enterprise systems (L4/L5) reach the "
   "control zone (L2), in one session with nothing in an industrial DMZ breaking it. A compromised "
   "source - an internet-facing or enterprise host is the most exposed, but a DMZ or site-operations "
   "server that should only broker sessions counts too - can then talk to controllers directly, and "
   "the firewalls on the way each see only one adjacent crossing, so no single rule looks wrong. The "
   "severity follows the source band (internet > enterprise > DMZ / site operations) and the "
   "destination band (L0/L1 > L2); the finding names the narrowest policy as the change point.",
   "Terminate the flow on a DMZ host (jump host, historian replica, proxy) and let that host open a "
   "separate session into OT; then narrow or remove the policies that carry the direct path. If the "
   "flow is a documented, accepted exception, record it as such in Access Review.")
_e("chain_ot_upward_skip",
   "A field / control device opens sessions straight to site or enterprise systems. Initiating "
   "upward across several tiers lets compromised OT equipment reach IT (or carry data out) without "
   "the intermediate tiers terminating the session.",
   "Have the next tier pull the data (historian, SCADA) or relay it through the DMZ; restrict the "
   "policies to the documented initiator and destination.")
_e("dmz_bypass",
   "The site has an industrial DMZ, yet IT / remote users and site operations (L3) are joined "
   "directly. The DMZ only protects OT if every flow between the enterprise and operations is "
   "terminated or brokered there; one direct conduit makes the DMZ optional for an attacker.",
   "Broker the flow through a DMZ host (jump host, historian replica, proxy) or record a justified "
   "exception in Access Review.")
_e("access_path_permissive",
   "A reviewer classified this permitted path as broader than the documented need.",
   "Narrow the policies in the path to the documented sources, destinations and services.",
   "Closes when the path is narrowed or reclassified in Access Review.")
_e("dead_end_permit",
   "A permit lets traffic as far as the next boundary, where nothing carries it on. It delivers "
   "nothing today, but it is a leftover (the downstream rule was removed), a half-finished change "
   "or an over-broad upstream rule - one downstream change away from opening a real path.",
   "Remove the permit, complete the change it belongs to, or narrow it to what is actually needed.")
_e("vpn_direct_to_ot config_vpn_direct_to_ot remote_access_bypass session_remote_access_bypass",
   "Remote users reach control-zone equipment directly instead of through a jump host in the DMZ. "
   "Remote access is the most common entry route into OT; without a broker there is no single point "
   "to authenticate, record and cut off sessions, and a stolen VPN credential lands next to the PLCs.",
   "Restrict the VPN / remote-access policy to the DMZ jump host and broker OT access from there "
   "(with session recording and approval for vendor access).")
_e("config_vpn_destination_unclear",
   "The VPN policy's destination interface has no Purdue level, so the app cannot tell whether "
   "remote sessions stop in the DMZ or continue into OT.",
   "Label the destination interface's Purdue level on the FW Topology page; the check is then "
   "re-judged automatically.")
_e("flat_control_segment",
   "Controllers (L1) share a subnet / VLAN - or, from a capture alone, one layer-2 segment - with "
   "other hosts and no firewall separates them, so every HMI, historian or workstation there can "
   "reach every controller, and any exposure of those hosts is an exposure of the controllers. With "
   "an L1/L2 segment this is legitimate only as a deliberate cell/area zone; site-operations or "
   "office hosts on it are never.",
   "Declare an L1/L2 segment a cell/area zone (Mgmt & Engineering page) if it is a deliberate design "
   "with one target security level; otherwise put the controllers behind their own boundary and move "
   "L3+ hosts off the segment. Classify any unclassified member.",
   "Closes when the segment is declared a cell/area zone, or when the controllers are separated.")
_e("path_ot_internet_egress ot_internet_egress session_ot_internet_egress",
   "An OT zone (site operations L3 included) can open sessions to the internet. That is a ready "
   "channel for malware download, command-and-control and data exfiltration, and it bypasses every "
   "DMZ control.",
   "Remove direct internet access; route the updates or services needed through an approved DMZ "
   "proxy / relay.")
_e("nat_hides_source_into_ot",
   "Traffic enters OT with its source translated to the firewall's address. The OT devices, their "
   "logs and any capture behind the firewall cannot tell who connected - nothing should enter OT "
   "without accountability.",
   "Remove the source NAT on paths into OT and route the real addresses, or keep the firewall's "
   "session log (with the original source) where the OT side can be audited.")
_e("config_vip_unused",
   "A virtual IP publishes an inside address on the firewall but no policy uses it: a leftover or a "
   "half-finished change, one policy away from exposing the mapped host.",
   "Delete the VIP, or document the change it belongs to.")
_e("rule_implicit_permit",
   "The firewall lets traffic through without a written rule: an ASA permits every connection from a "
   "higher to a lower security level when no access list is bound inbound on the interface. Nothing in "
   "the policy states this permit, it allows every service, and reviews of the written rules never see it.",
   "Bind an inbound ACL to the interface that permits only the documented conduits and ends in an "
   "explicit deny.")
_e("switch_routes_between_zones",
   "A switch with SVIs in VLANs of different Purdue levels routes between them itself, so that "
   "traffic never reaches the firewall that was meant to separate the zones. The boundary exists on "
   "paper only: the switch forwards everything its (stateless, often absent) access lists do not drop.",
   "Remove the OT VLANs' SVIs from the switch (or disable ip routing on it) so the firewall is the only "
   "gateway between zones; if the switch must route, put the boundary on a firewall instead.")
_e("switch_acl_wrong_direction",
   "The access list meant to protect an OT VLAN is applied 'in' on its SVI, which filters packets "
   "coming FROM the VLAN's hosts. Traffic routed INTO the VLAN from other VLANs is not filtered at all, "
   "so the protection the ACL describes does not exist.",
   "Apply the ACL 'out' on the OT VLAN's SVI (or an equivalent ACL 'in' on every other SVI).")
_e("switch_mgmt_svi_unrestricted",
   "The management VLAN has a routed SVI with no access list, so every routed VLAN - IT included - can "
   "reach the management interfaces of the devices on it.",
   "Bind an ACL 'out' on the management SVI that admits only the management workstations / jump hosts, "
   "or stop routing the management VLAN.")
_e("switch_dual_gateway",
   "An OT network has two gateways: a firewall interface and a switch SVI. Each host's default gateway "
   "decides which one carries its traffic, so the firewall policy only applies to the hosts that happen "
   "to point at the firewall.",
   "Keep the firewall as the only gateway: remove the SVI's address (or ip routing) on the switch, and "
   "check the hosts' gateway settings.")
_e("historian_in_control_zone misplaced_device vlan_zone_mismatch",
   "A device sits in a zone that does not match its role or level, so the zone's rules no longer "
   "describe what is really there - e.g. a historian (an IT-facing server) inside the control zone "
   "brings IT traffic next to the controllers.",
   "Move the device to the zone of its level (or correct its classification if the app's "
   "inference is wrong).")
_e("config_no_internal_segmentation",
   "Only the perimeter is firewalled; once inside OT, everything can reach everything.",
   "Add boundaries between OT zones (control cells, safety, site operations).")
_e("config_wireless_not_isolated wireless_in_ot_zone",
   "Wireless extends the OT network beyond its physical boundary; inside a control zone it is an "
   "entry point that bypasses the firewalls. A consumer Wi-Fi router or access point plugged into "
   "the network (TP-Link, Netgear ... in a capture) lets every phone or laptop that joins it in.",
   "Put wireless in its own zone behind the firewall, or remove it from the control zone; remove "
   "consumer network equipment.")
_e("config_possible_dual_homed",
   "A host with interfaces on both sides of a boundary bridges the zones itself, bypassing the "
   "firewall.",
   "Remove the second interface or put the host in the DMZ with the firewall between its legs.")
_e("config_same_zone_rule",
   "A policy whose source and destination are the same zone does not enforce a boundary; it hides "
   "intent and is often a mistake.",
   "Remove it, or replace it with the specific inter-zone policy that was meant.")

# --- management / engineering -------------------------------------------------
_e("mgmt_access_from_wrong_zone rule_mgmt_wrong_zone chain_mgmt_wrong_zone session_mgmt_from_non_admin "
   "auth_from_non_admin_host mgmt_access_not_restricted",
   "Management protocols (SSH, RDP, HTTPS, SNMP, Telnet) reach OT equipment from hosts outside a "
   "dedicated management or engineering zone. Administrative access is what an attacker needs to "
   "change controllers and network devices; it must come only from controlled admin / engineering "
   "workstations or jump hosts.",
   "Restrict the source to the management / engineering network or jump host. If the source IS a "
   "legitimate admin or engineering host, declare it (Fix on the finding, or the Mgmt & Engineering "
   "page) and the check re-runs.",
   "Closes when the source is declared a management / engineering source, or the access is removed.")
_e("config_mgmt_not_restricted_to_mgmt_zone",
   "The firewall accepts HTTPS / SSH administration on an interface that is not a management zone, "
   "so anyone who reaches that network can attack the firewall's own login.",
   "Remove admin access (allowaccess) from that interface, or reclassify it as a management zone if "
   "it is one (Fix on the finding).",
   "Closes on the next config upload without the condition, or when the interface is declared a "
   "management zone.")
_e("config_admin_no_trusted_hosts config_admin_trusthost_too_broad config_admin_trusthost_outside_mgmt",
   "Firewall administrator accounts accept logins from anywhere (or from a very wide range / outside "
   "the management networks); the trusted-host list is the last line of defence for the firewall's "
   "own management plane.",
   "Set trusthost entries for every admin account to the management network / admin workstations.")
_e("config_insecure_mgmt_protocol switch_insecure_mgmt_protocol",
   "Management over HTTP / Telnet sends passwords and configuration in cleartext; anyone on the path "
   "can capture them.",
   "Disable HTTP / Telnet administration; use HTTPS and SSH only.")
_e("switch_port_no_nac",
   "Enabled access ports of a FortiLink-managed or standalone FortiSwitch have no port-security (802.1X / MAC authentication) "
   "policy: any device plugged in joins the VLAN. Medium when such ports sit on VLANs labelled L0-L2; uplinks, "
   "trunks and ports set down are not counted. A policy with open-auth or MAC-auth-bypass enabled exists but does "
   "not authenticate.",
   "Bind a port-security policy (config switch-controller security-policy 802-1X) to the access ports - 802.1X with "
   "MAC authentication bypass only for devices that cannot do 802.1X, no open-auth - or document the ports that must "
   "stay open and why.",
   "Closes at the next review once every enabled access port of the switch has a policy (re-upload the FortiGate "
   "configuration after the change).")
_e("switch_unused_port_enabled",
   "Access ports of a FortiLink-managed or standalone FortiSwitch are enabled with no description, no neighbour and no MAC address "
   "ever seen on them in the uploaded MAC tables: open sockets for anyone with physical access.",
   "Shut unused ports down (set status down on the managed-switch port) or give them a description that says what "
   "they are reserved for; upload the switch's MAC table so ports in use are recognised.",
   "Closes at the next review once the ports are down, described, or show a MAC address.")
_e("switch_snmp_default_community",
   "The switch accepts a vendor-default / well-known SNMP community; anyone who can reach it can "
   "read (or with write access change) its configuration, VLANs and neighbours.",
   "Remove the default community; use SNMPv3 with authentication and privacy.")
_e("switch_snmp_cleartext_community",
   "SNMPv1/v2c sends the community string in cleartext on every poll.",
   "Move to SNMPv3 with authentication and privacy.")
_e("config_no_password_policy config_weak_password_policy",
   "Without an enforced password policy administrators can keep short or default passwords on the "
   "device that guards the OT boundary.",
   "Configure system password-policy (length, complexity, expiry) and change default credentials.")
_e("config_no_admin_lockout config_admin_lockout_threshold_high",
   "Without account lockout the firewall's admin login can be brute-forced indefinitely.",
   "Set admin-lockout-threshold (e.g. 3-5) and admin-lockout-duration.")
_e("config_no_admin_idle_timeout config_admin_idle_timeout_long",
   "Admin sessions that never time out leave an authenticated console open for anyone who walks up "
   "to it or hijacks it.",
   "Set admintimeout (e.g. 5-15 minutes).")
_e("config_no_central_auth",
   "With only local accounts there is no central control or audit of who administers the firewall; "
   "leavers keep access until someone edits every device.",
   "Authenticate administrators through RADIUS / TACACS+ (with MFA where possible).")
_e("config_maintainer_account_enabled config_maintainer_named_account",
   "The maintainer account allows a password reset from the console with physical access; on an "
   "unattended site that is a bypass of every admin control.",
   "Disable the maintainer account, or accept the risk with documented physical controls.")
_e("config_unused_interface_not_disabled",
   "An unused but enabled interface is a ready-made way into the firewall for anyone with physical "
   "access.",
   "Set unused interfaces to status down.")

# --- remote access ---------------------------------------------------------------
_e("config_vpn_source_unrestricted",
   "Any internet address can attempt to log in to the VPN; vendor and IT remote access should be "
   "limited to known sources and enabled on request.",
   "Restrict ssl-vpn source-address to known ranges; enable vendor access only when needed.")
_e("config_vpn_no_idle_timeout config_vpn_idle_timeout_long",
   "Remote sessions that stay open for hours keep an authenticated path into OT open after the user "
   "has left.",
   "Set the SSL-VPN idle-timeout (e.g. 15-30 minutes) and a maximum session time.")
_e("config_vpn_no_routing_policy",
   "No firewall policy governs where SSL-VPN users go, so their reach is undefined.",
   "Add explicit tunnel policies that send VPN users to the DMZ jump host only.")
_e("config_split_tunneling_enabled",
   "With split tunnelling the remote PC talks to the internet and to OT at the same time; it becomes "
   "a bridge between them.",
   "Disable split-tunneling on the tunnel-mode portals used for OT access.")
_e("config_vpn_shared_access",
   "IT and vendor VPN users get addresses from the same pool, so traffic seen inside the network "
   "cannot be attributed to one group, and no policy after the VPN firewall can treat them "
   "differently.",
   "Give each group its own portal and tunnel pool (config authentication-rule → portal → ip-pools).")
_e("config_local_in_permits_all",
   "A local-in policy decides which traffic may reach the firewall itself. Accepting every service "
   "hands its management, routing and VPN daemons to those sources; only the interface's allowaccess "
   "list still stands between them and the admin services. Each source is placed against this firewall: an "
   "interface network or a routed network is inside the site; a public address, a network behind an IPsec / "
   "SSL-VPN tunnel (selector, client pool or tunnel route) or a private address the firewall has no path to "
   "is outside it.",
   "Limit the local-in policy to the services it exists for (IKE, ICMP, HTTPS/SSH from the admin "
   "hosts) and keep the default deny below it.")
_e("config_ipsec_peer_unrestricted",
   "With certificate authentication and peertype any, every certificate the firewall trusts can "
   "bring up this tunnel - not only the intended peer's.",
   "Set peertype one / peer (a user peer that pins the peer's certificate subject or CA).")
_e("config_ipsec_dialup_psk",
   "Every dial-up client knows the same pre-shared key; anyone who obtains it from one client can "
   "attempt the tunnel, and leaving users cannot be revoked individually at that layer.",
   "Use certificate authentication for the dial-up phase1 (keep EAP / SAML user authentication on top), "
   "or rotate the key and keep it out of shared client profiles.")
_e("config_service_protocol_mismatch",
   "The service's name says one transport but it is defined as the other, so the policies using it "
   "do not allow what their author intended and allow a port nobody asked for.",
   "Correct the service definition (or its name) and check the policies that use it.")
_e("config_remote_session_not_logged",
   "Remote sessions are not logged, so there is no record of who accessed OT remotely and what they "
   "did.",
   "Enable traffic logging on the remote-access policies (and session recording on the jump host).")
_e("remote_access_app",
   "An unapproved remote-access application (TeamViewer, AnyDesk ...) creates its own tunnel through "
   "the firewall, outside every remote-access control.",
   "Block unapproved remote-access applications; use the approved jump-host path.")

# --- rules / policy hygiene ----------------------------------------------------------
_e("config_permit_any_any_any cross_fw_any_any_permit",
   "The policy permits 'all' in its source, destination or service (critical when all three): the "
   "boundary lets through more than the documented flows - into OT or out to the Internet it is high.",
   "Replace 'all' with the specific hosts, networks and services the conduit needs, or record the "
   "justification (acknowledge the finding with a note).")
_e("config_temporary_rule",
   "A policy meant to be temporary has no end: its schedule never expires (always / recurring), or "
   "its one-time schedule has already ended while the policy stays enabled. Temporary access that "
   "outlives its need is a standing hole in the boundary.",
   "Give the policy a one-time schedule ending when the work ends, or remove it; remove expired "
   "policies.")
_e("config_overly_broad_subnet",
   "A policy allows a whole /16 (or wider) where specific hosts are known, permitting far more "
   "systems than the conduit needs.",
   "Replace the broad subnet with the specific hosts / address groups that need the access.")
_e("rule_cleartext_protocol cleartext_protocol smbv1_legacy",
   "Cleartext or legacy protocols (Telnet, FTP, HTTP, SNMPv1/2, SMBv1) cross a zone boundary; their "
   "credentials and commands can be read or altered on the wire.",
   "Remove them from the conduit or replace them with secure equivalents (SSH, SFTP, HTTPS, SNMPv3).")
_e("rule_mgmt_protocol mgmt_protocol",
   "A management protocol (SSH, Telnet, SNMP, RDP, VNC, WinRM) crosses a zone boundary. Whoever can "
   "use it can reconfigure the device on the far side; cleartext ones (Telnet, SNMPv1/2c) also expose "
   "the credentials on the wire.",
   "Allow management only from the dedicated management zone or jump host, over encrypted protocols "
   "(SSH, HTTPS, SNMPv3); remove the rest from the conduit.")
_e("rule_cleartext_creds cleartext_credentials",
   "Protocols that send credentials in cleartext reach OT hosts; captured passwords give an attacker "
   "operator access.",
   "Block the cleartext protocols into OT; use encrypted alternatives.")
_e("config_email_web_to_ot",
   "Email or web browsing into / from control zones is the classic phishing and drive-by route into "
   "OT.",
   "Block email, web and chat services into and out of control zones.")
_e("unused_policy disabled_rule",
   "A permit that no observed traffic uses (or a disabled rule kept in the policy) widens the attack "
   "surface without serving a purpose, and makes the policy harder to review.",
   "Confirm with the owner and remove it (or document why it is needed and how rarely it is used).")
_e("shadow_rule",
   "A rule can never match because an earlier rule already takes all its traffic; the policy does "
   "not do what it says, which hides mistakes in reviews.",
   "Remove the shadowed rule, or reorder / narrow the earlier one if the later rule was the intent.")
_e("rule_conduit_drift conduit_matrix_drift session_no_permitting_rule",
   "What the firewalls permit (or what the capture shows) differs from the documented "
   "communications matrix: either the documentation is out of date or traffic flows that nobody "
   "approved.",
   "Reconcile: approve and document the flow, or remove the policy / stop the traffic.")
_e("rule_ot_it_dependency ot_it_dependency",
   "OT depends on IT services (DNS, AD, NTP, file shares) across the boundary; an IT outage or "
   "compromise then affects operations, and the conduit is a path back into OT.",
   "Provide those services inside OT (local DNS, NTP, AD replica) or through the DMZ.")
_e("config_broadcast_cross_zone",
   "Broadcast / multicast is permitted across a zone boundary, leaking discovery and industrial "
   "multicast traffic between zones.",
   "Remove the broadcast / multicast destinations from inter-zone policies.")
_e("config_rules_missing_owner",
   "Rules without an owner or justification cannot be reviewed: nobody can say whether they are "
   "still needed.",
   "Add the owner / ticket / justification to each rule's comments.")
_e("fqdn_in_policy",
   "A policy depends on DNS resolution; whoever controls DNS controls what the rule permits.",
   "Use concrete addresses for OT conduits.")
_e("config_logging_disabled",
   "The policy does not log, so traffic through this conduit leaves no evidence for investigation "
   "or monitoring.",
   "Set logtraffic all (or utm) on every conduit policy.")
_e("cross_fw_no_rules cross_fw_missing_deny_all",
   "A firewall on a confirmed link has no rules loaded (or no explicit deny-all); its behaviour on "
   "that boundary cannot be verified.",
   "Load the firewall's configuration (and add an explicit, logged deny-all).")
_e("cross_fw_asymmetric_permit",
   "Two firewalls in series enforce one boundary, but one permits a flow the other does not: either "
   "the permit is dead (blocked by the partner) or the partner is missing a rule - the pair's intent "
   "is unclear.",
   "Make both firewalls of the pair agree: add the matching rule or remove the unmatched one.")
_e("cross_fw_same_permit_both_sides",
   "Both firewalls of a link carry the same permit (informational: expected for a paired boundary).",
   "No action needed unless the duplication is unintended.")
_e("paired_firewall_vendor_diversity",
   "Two firewalls in series give defence in depth only if one vendor's vulnerability or a shared "
   "misconfiguration cannot open both.",
   "Confirm the vendors in an attestation (PF-<id>), or accept a single-vendor pair by acknowledging.",
   "Closes with a current attestation; acknowledging accepts the single-vendor pair.")
_e("access_path_enumeration_truncated",
   "The permitted-path list stopped at its row budget, so the chain reviews (IT/OT bypass, "
   "management from the wrong zone, upward skips, dead ends, DMZ bypass, internet egress) judged "
   "only part of the site's paths; a crossing that is not listed is not a pass.",
   "Raise IACS_MAX_ACCESS_PATH_ROWS, or split the site, or tighten over-broad policies so fewer "
   "rows are enumerated, then re-run the reviews.",
   "Closes when a review run completes the enumeration within the budget.")
_e("ha_config_drift",
   "A member of an HA cluster runs a different policy than the primary; after a failover the "
   "boundary behaves differently.",
   "Synchronise the cluster configuration.")

# --- traffic / devices -------------------------------------------------------------
_e("unauthorized_industrial_write unauth_ot_write",
   "A host that is not an approved engineering workstation or HMI wrote to (or programmed / "
   "stopped) a controller. Writes change the physical process; only authorised hosts may issue them.",
   "Block industrial writes from that source (firewall / DPI). If the source is a legitimate "
   "engineering host, add it as an engineering workstation (Fix on the finding).",
   "Closes when the source is approved (baseline engineering_ws / hmi or a declared engineering "
   "source), or when the session is re-attributed (NAT).")
_e("unknown_device ghost_vlan undocumented_lldp_device",
   "A device on the network is not in the asset inventory - or, with no inventory loaded, a host "
   "acting as industrial client (Modbus / S7 / CIP master) that nobody has identified. Unknown devices "
   "are unmanaged (unpatched, unmonitored) and may be rogue.",
   "Identify the device and add it to the inventory / baseline, or remove it from the network.")
_e("multi_homed_host",
   "One network card carries addresses in several subnets. The device bridges those subnets: anything "
   "that compromises it reaches every one of them, and the subnets are not separated at all on that "
   "wire.",
   "Give the device one address per physical interface and route between the subnets through a "
   "firewall, or document the dual-homing with its compensating controls.",
   "Closes when the next capture review no longer sees the extra addresses.")
_e("undocumented_conduit",
   "Two documented IEC 62443 zones exchange traffic (a firewall policy permits it, or captures show "
   "it) and no conduit is documented between them. 62443-3-2 treats every path between zones as a "
   "conduit with its own security requirements; an undocumented one is a gap in the zone design or "
   "a path nobody intended.",
   "On Zones & Conduits, document the conduit (name, SL-T, purpose) if the communication is "
   "designed, or remove the permitting policies and stop the traffic if it is not.",
   "Closes when the conduit is documented or the policies and traffic between the zones are gone.")
_e("host_in_multiple_zones",
   "One device (every address of a MAC) is documented in two or more IEC 62443 zones - as a host "
   "member of each, or through its addresses' networks. 62443-3-2 partitions the system: a zone's "
   "security requirements and SL-T apply to an asset that belongs to it and to no other. A device in "
   "two zones is either dual-homed (it bridges them) or a documentation error; either way its "
   "requirements are undefined.",
   "Decide which zone the device belongs to and remove it from the others (Zones & Conduits: the zone "
   "panel, or 'move'). If it really spans two zones, give it one address per zone and document the "
   "dual-homing as a conduit with its compensating controls.",
   "Closes when the device resolves to one zone.")
_e("network_in_multiple_zones",
   "The same network (subnet, firewall interface network or FortiGate zone member) is a member of two "
   "or more IEC 62443 zones, so every host on it is claimed by both. The page resolves hosts to the "
   "first zone listed, but the zone documentation itself is contradictory.",
   "Keep the network in the zone it belongs to and remove it from the others; split the network, or "
   "use host members, if its hosts really belong to different zones.",
   "Closes when the network is a member of one zone.")
_e("policy_spans_multiple_conduits",
   "One firewall policy permits traffic for two or more IEC 62443 zone pairs at once (for example "
   "srcintf port1 and port2 into port3, where port1 and port2 belong to different zones). Each zone "
   "pair is its own conduit with its own purpose and security requirements; a single rule carrying "
   "several cannot be scoped to any one conduit's services or sources, and tightening it for one "
   "zone silently changes the other.",
   "Split the policy into one policy per conduit (one source zone and one destination zone each), "
   "then document each conduit with its services on Zones & Conduits.",
   "Closes when no policy maps to more than one zone pair.")
_e("blocked_cross_zone_attempts",
   "A host tried to reach other IEC 62443 zones (or other firewall segments) and every attempt was "
   "dropped - no answer or refused, and no session on that port got through. The firewall did its job, "
   "but a host probing other zones is either misconfigured or exploring the network; when nobody has "
   "identified it and it tries management or file-sharing ports (RDP, SSH, SMB ...), it looks like "
   "reconnaissance. Attempts on a zone pair with no documented conduit, or for a service the conduit "
   "does not list, are paths nobody designed.",
   "Identify the host (Inventory: classify it or approve it, or remove it from the network) and find out "
   "why it tries these services. If the traffic is legitimate, document the conduit with the service and "
   "permit it deliberately.",
   "Closes when the attempts no longer appear in the captures (re-upload) or the host is removed.")
_e("conduit_service_blocked",
   "A documented conduit lists this service (and source), but the firewall dropped the attempt: the zone "
   "documentation and the firewall policy disagree.",
   "Align the two: add the permitting policy, or remove the service from the conduit if it is no longer "
   "intended.",
   "Closes when the attempt no longer appears or the conduit no longer lists the service.")
_e("rogue_dhcp_server",
   "A device hands out IP addresses (DHCP offers / acks) on the network. In a statically addressed "
   "control network that is usually a consumer router or access point: it can give hosts a wrong "
   "gateway or DNS server and steer their traffic.",
   "Find the device (MAC in the evidence) and switch its DHCP server off or remove it. Where DHCP is "
   "needed, run it on one managed server and enable DHCP snooping on the switches.",
   "Closes when the next capture review no longer sees DHCP replies from it.")
_e("dead_default_gateway",
   "Several hosts keep asking (ARP) for an address nobody answers: a default gateway that does not "
   "exist. Whoever takes that address becomes their router - a man-in-the-middle and a way out.",
   "Remove the gateway from the hosts' configuration (empty on an isolated network), or reserve the "
   "address on a device you control.",
   "Closes when the address answers or the hosts stop asking.")
_e("ip_conflict",
   "Two devices answer for one IP address: a misconfiguration or spoofing, either of which can "
   "redirect OT traffic.",
   "Find both devices (MAC addresses in the evidence) and correct the addressing.")
_e("session_remote_access_app",
   "A host inside the plant holds a session with a remote-access tool (TeamViewer, AnyDesk, VNC, "
   "RDP ...) to or from the Internet. That channel bypasses the DMZ jump host and every control on "
   "it - MFA, approval, session recording - and anyone with the tool's credentials is on the OT "
   "network.",
   "Remove the tool from the host, or route vendor access through the approved remote-access path "
   "(jump host in the DMZ). Block the tool's ports and domains at the boundary.",
   "Closes when the next review no longer sees the session.")
_e("engineering_access_unapproved",
   "A host classified as an engineering workstation works on controllers or supervisory equipment, "
   "but it is not an approved engineering source. Engineering access is expected - from the "
   "sanctioned engineering stations only; an unapproved one is either a missing approval or a "
   "machine that should not be programming the plant.",
   "If it is the sanctioned engineering station, approve it: Mgmt & Engineering - trusted host with "
   "purpose engineering (or the baseline's engineering_ws role). Otherwise re-classify the host and "
   "investigate the access.",
   "Closes at the next review run once the workstation is an approved engineering source, or when it "
   "is no longer classified as an engineering workstation.")
_e("scanning_denied session_scanning_anomaly",
   "One source touches many hosts or ports - including refused or unanswered connection attempts and "
   "ARP requests to empty addresses: scanning, worm activity or a misconfigured tool.",
   "Identify the source and the reason; block it if unexplained.")
_e("denied_trend",
   "Summary of denied traffic (informational): evidence that default-deny works, and of who keeps "
   "trying.",
   "Review the top sources; investigate any unexplained one.")
_e("ntp_sync config_ntp_fortiguard",
   "Time comes from outside the site - FortiGuard, or custom NTP servers at public addresses / pool names - "
   "instead of an internal source; that needs Internet egress, makes log timestamps and certificate checks "
   "depend on an external service and, with server-mode, hands that dependency to the OT networks the firewall "
   "serves. Each configured server is placed: local (an interface network of this firewall), internal (reached by "
   "a static route or a private address) or external. FortiGuard alone is informational on a firewall with an "
   "Internet leg and low without one; external custom servers are medium with a WAN leg, low without, high when "
   "no internal source exists and the firewall serves time to OT interfaces.",
   "Keep the internal server (stratum-2 / GPS / PTP grandmaster), remove the public pools, enable NTP "
   "authentication, and let OT interfaces take time from the internal source.")
_e("config_dns_external",
   "The firewall resolves names through external DNS (a public server, or the FortiGuard servers when none is "
   "configured), an egress path and a dependency on outside infrastructure. FortiGuard DNS is informational "
   "on a firewall with an Internet leg and low on an internal one; it is raised when permit rules use FQDN "
   "objects (the resolver then decides what is allowed - medium into OT). A third-party public resolver is medium.",
   "Set internal resolvers under config system dns.")
_e("rule_dns_external",
   "A policy lets hosts query an external DNS server (tcp / udp 53 to a public address or name): an egress path, "
   "a dependency on the Internet and a channel that is rarely inspected; from an OT zone it also breaks the rule "
   "that no OT device reaches the Internet directly.",
   "Point the hosts at an internal resolver (or a DMZ forwarder) and remove the public servers from the policy.")
_e("single_path_critical_device no_path_redundancy_verified",
   "A critical device has one network path; a single cable, port or switch failure stops it.",
   "Add a redundant path (dual-homing / ring) or document and test the accepted risk.")
_e("firmware_not_documented",
   "Firmware versions are not documented, so known vulnerabilities cannot be tracked.",
   "Record firmware versions in the asset inventory.")

# --- logging / availability / hardening -------------------------------------------
_e("config_no_syslog_forwarding log_silence",
   "Logs stay on the device (or stop arriving); evidence is lost when the device is reset or "
   "compromised, and nobody is alerted. (Any syslog server 1-4, FortiAnalyzer or FortiGate Cloud "
   "destination counts as forwarding.)",
   "Forward logs to the SIEM / FortiAnalyzer and alert on silence.")
_e("config_syslog_unencrypted",
   "Logs travel in cleartext and over UDP: readable, forgeable and lossy. Each listed destination "
   "(syslog, FortiAnalyzer, cloud) is judged on its own settings.",
   "Use reliable, encrypted log transport (TLS / OFTP).")
_e("config_monitoring_readiness",
   "Continuous monitoring (SR 6.2) and auditable events (SR 2.8) need the firewall to record what "
   "crosses the boundary and what happens to the firewall itself, and to send it off the box. The "
   "listed gaps leave holes in that record: implicit-deny hits, attempts on the firewall, admin / "
   "configuration events, sessions of policies logging security events only, or traffic logs that "
   "never leave the device. Logs uploaded to an Internet service take OT details off site.",
   "Enable log setting fwpolicy-implicit-log and local-in-deny-unicast, keep the event filter "
   "categories on, set logtraffic all on OT conduit policies, send traffic logs to an internal "
   "FortiAnalyzer / SIEM.")
_e("fw_config_change",
   "The firewall configuration changed (informational / review): every change to the OT boundary "
   "should match an approved change record.",
   "Match the change to its change record; investigate if there is none.")
_e("auth_failure",
   "Repeated failed logins to the firewall: password guessing, or an account / script with a stale "
   "password.",
   "Investigate the source; enforce lockout and trusted hosts.")
_e("ips_ot_conduit",
   "IPS detected an attack signature on an OT conduit.",
   "Investigate the event and the source host.")
_e("config_ids_ips_missing config_industrial_dpi_missing",
   "Traffic on this conduit is not inspected (no IPS / industrial-protocol DPI sensor), so attacks "
   "and malicious industrial commands pass unseen.",
   "Apply an IPS sensor (with industrial signatures) to the conduit policy.")
_e("config_av_missing_on_file_policy config_no_av_profile config_av_profile_not_applied",
   "Files cross the conduit without anti-malware inspection.",
   "Configure an AV profile and apply it to the conduit policies carrying file content.")
_e("config_rsp_check_disabled",
   "Anti-spoofing (reverse-path check) is off, so packets with forged source addresses are accepted.",
   "Enable strict reverse-path checking on OT interfaces.")
_e("config_fail_open_enabled",
   "The firewall passes traffic when its inspection fails: under load or attack the boundary opens.",
   "Disable fail-open for OT conduits.")
_e("config_no_scheduled_backup",
   "Without a scheduled offsite backup the only copy of the boundary's configuration is the device.",
   "Schedule configuration backups to an offsite destination (or FortiManager).")
_e("config_strong_crypto_disabled",
   "strong-crypto is disabled, so the management GUI, SSH, SSL-VPN and IPsec accept weak ciphers, short "
   "keys and old protocol versions.",
   "Set 'strong-crypto enable' under config system global and re-check the TLS / SSH versions.")
_e("config_snmp_v1v2c_enabled",
   "SNMP v1 / v2c communities send the community string in cleartext and have no user authentication - "
   "anyone on the management path can read (or, with write access, change) the device.",
   "Remove the communities and use SNMPv3 with authPriv users restricted to the monitoring hosts.")
_e("config_snmp_default_community",
   "The community string is 'public' or 'private' - the first values any scanner tries.",
   "Change the community (better: move to SNMPv3) and restrict the allowed hosts.")
_e("config_admin_no_two_factor",
   "A local administrator of the built-in user database logs in with a password only; a phished or reused "
   "password gives full control of the firewall (high when the account holds super_admin).",
   "Enable two-factor (FortiToken Mobile, hardware token, FortiToken Cloud, e-mail or SMS) on the account or make "
   "it a remote RADIUS / TACACS+ admin on a server that enforces MFA; remove unused local admins.")
_e("config_fortimanager_admin_access",
   "The device is managed by FortiManager: administrators reach it through the FortiManager tunnel with "
   "FortiManager accounts, so the MFA that protects administrative access lives on FortiManager, which this "
   "configuration cannot show. A FortiManager at a public address raises it to low; a name is reported, not judged.",
   "Confirm that every FortiManager administrator account uses two-factor authentication (FortiToken or a RADIUS / "
   "SAML server enforcing MFA) and that the FortiManager is reachable from the management network only; then "
   "acknowledge this finding with the evidence.",
   "Stays open while the device is managed by FortiManager: acknowledge it once MFA on FortiManager is confirmed "
   "(a re-upload without central management closes it).")
_e("config_admin_profile_overprivileged",
   "More than two administrators hold super_admin; operators, auditors and helpdesk do not need full rights.",
   "Create scoped access profiles (config system accprofile) and keep super_admin for one owner and one "
   "break-glass account.")
_e("config_no_login_banner",
   "No system-use notification is shown before login (SR 1.12); users are not warned that access is "
   "monitored and restricted.",
   "Enable pre-login-banner (and post-login-banner) and set the banner text under config system replacemsg.")
_e("config_ha_no_monitor_interfaces",
   "The HA cluster monitors no interfaces, so a failed OT-facing link does not trigger a failover.",
   "Add the production interfaces to 'set monitor' under config system ha and test the failover.")
_e("config_policy_any_interface",
   "The policy is bound to interface 'any' on one side, so it applies between every pair of interfaces: it "
   "belongs to no single conduit and its direction cannot be judged.",
   "Bind the policy to the specific source and destination interfaces / zones.")
_e("config_device_detection_disabled",
   "Device detection is off on routed interfaces; the FortiGate's own view of the hosts behind them (vendor, OS) "
   "is not available to the inventory.",
   "Enable device-identification on the OT-facing interfaces (information only - no traffic impact).")
_e("config_ntp_unauthenticated",
   "The custom NTP servers are used without authentication; a spoofed source can shift the clock that log "
   "timestamps and certificate validity depend on.",
   "Enable NTP authentication (key) on each server entry, or sync from a trusted internal source.")
_e("config_no_revision_backup",
   "Configuration revisions are not kept on logout and no FortiManager holds them, so a change cannot be "
   "diffed against the approved baseline or rolled back.",
   "Enable revision-backup-on-logout (and revision-image-auto-backup) or manage the device from FortiManager.")
_e("config_vendor_rule_permanent",
   "The remote-access (vendor / VPN) policy has schedule 'always'; the access does not end with the work order.",
   "Give vendor policies a one-time or recurring schedule and disable them between interventions.")
_e("config_icmp_across_boundary",
   "The policy permits ICMP (ping / all ICMP) across a zone boundary, which lets hosts map the other side.",
   "Restrict ICMP to the monitoring hosts that need it, or remove the policy.")
_e("config_implicit_deny_not_logged",
   "Traffic hitting the implicit deny is not logged, so blocked attempts and scans across the boundary leave "
   "no record for monitoring.",
   "Set 'fwpolicy-implicit-log enable' under config log setting and forward the deny logs.")
_e("config_vpn_user_no_mfa",
   "Users in a remote-access (SSL-VPN / dial-up) group log in with a password only - from the built-in user "
   "database or from an LDAP server, which is still one factor; a phished or reused password opens the VPN "
   "into the plant. A group member that is a SAML identity provider is MFA when it is FortiTrust ID (Fortinet's "
   "cloud identity service); any other SAML / FSSO provider is reported as 'MFA not visible'.",
   "Enable FortiToken / e-mail / SMS two-factor on each user (local or LDAP-mapped), or move the group to a "
   "RADIUS / TACACS+ server that enforces MFA.")
_e("config_wireless_weak_security",
   "The SSID's security is open, WEP, WPA(1) or a captive portal (anyone in range can join or decrypt it - high when "
   "the SSID lands in an OT network), or - on an OT SSID - a WPA2/WPA3 pre-shared key: one secret shared by every "
   "device and every leaver, whose strength the configuration does not reveal (passphrases are stored encrypted). "
   "Whether an SSID is in OT comes from the Purdue label of the interface / VLAN it lands on (FW Topology Builder).",
   "Use WPA2/WPA3-Enterprise (802.1X) with per-device credentials and PMF for OT wireless; remove WEP / open SSIDs; "
   "where a pre-shared key must stay, document its length / rotation policy and keep the SSID out of OT VLANs.")
_e("config_weak_ipsec_crypto",
   "The IPsec tunnel negotiates DES / 3DES / MD5, DH groups 1-5, SHA1 integrity or no PFS: an attacker who "
   "records the traffic can break or replay it.",
   "Set AES-GCM or AES-256 with SHA-256 or better, DH group 14+ (19-21 ECP), PFS enabled, on phase1 and phase2.")
_e("config_sslvpn_weak_tls",
   "The SSL-VPN accepts TLS 1.0 / 1.1 or low / medium strength cipher suites, exposing remote sessions to "
   "downgrade and known cipher attacks.",
   "Set ssl-min-proto-ver tls1-2 (or tls1-3) and algorithm high under config vpn ssl settings.")
_e("config_no_dos_policy_ot",
   "No DoS policy protects the OT-facing interfaces: a misbehaving or compromised host can flood the "
   "controllers and the firewall sessions table.",
   "Create a firewall DoS-policy per OT interface with flood / scan thresholds and logging.")
_e("config_wireless_weak_security",
   "The SSID uses open, WEP or WPA(1) security, which anyone in radio range can join or decrypt.",
   "Use WPA2/WPA3-Enterprise (802.1X) for OT wireless and keep it in its own zone.")
_e("sis_zone_not_isolated",
   "A safety instrumented system is reachable from, permitted from, or shares a network with hosts that are "
   "not part of the safety system or its engineering workstation; a compromise of those hosts reaches the "
   "protection layer.",
   "Put the SIS in its own zone (interface / VLAN), restrict the permit rules to the safety engineering "
   "workstation, and move the other hosts off its network.",
   close="Closes at the next review when no such session, rule or shared network remains.")
_e("transient_device_in_ot_zone",
   "A laptop, PC or USB-Ethernet adapter (by its MAC vendor) sits on a control network without anyone "
   "having identified it; transient devices bring malware and uncontrolled changes into the zone.",
   "Identify it: approve it as engineering equipment in the inventory, move it to the transient-device "
   "zone, or remove it.",
   close="Closes at the next review once the host is classified, approved, excluded or gone.")
_e("default_credentials_observed",
   "A login with a well-known default user / password pair (or a default SNMP community) was seen on the "
   "wire; anyone can use the same credentials.",
   "Change the device's default credentials and move the service off the cleartext protocol.",
   close="Closes at the next review when no session with default credentials remains in the captures.")
_e("weak_tls_observed",
   "The server negotiated SSLv3 / TLS 1.0 / TLS 1.1 or SSH-1, which have known downgrade and cipher attacks.",
   "Raise the service's minimum to TLS 1.2 (SSH-2) and update the clients that cannot negotiate it.",
   close="Closes at the next review when no capture shows the weak version any more.")
_e("config_ha_no_auth",
   "The HA heartbeat is not authenticated / encrypted; a device on that link can join or disrupt "
   "the cluster.",
   "Set an HA password and encrypt the heartbeat.")
_e("ha_system_error ha_failover",
   "An HA event occurred (informational / availability): confirm it was expected.",
   "Review the event and the cluster state.")
_e("config_weak_tls_version",
   "Weak TLS versions / static-key ciphers are accepted on the management or VPN plane.",
   "Require TLS 1.2+ and disable static-key ciphers.")
_e("config_default_hostname config_no_timezone",
   "Without a hostname / timezone, logs from this device are hard to correlate during an "
   "investigation.",
   "Set the hostname and timezone.")
_e("config_usb_auto_install_config config_usb_auto_install_image",
   "A USB stick inserted at boot can replace the firewall's configuration or firmware - a physical "
   "bypass of every control.",
   "Disable USB auto-install.")
_e("config_wireless_in_ot",
   "A FortiAP SSID lands in an OT network - in tunnel mode its interface is labelled L0-L2, in bridge mode it is "
   "bridged to a VLAN whose interface is. A radio network inside the control zone is an ingress point that no cable "
   "or door controls, reachable from outside the fence. The judgement needs the wireless VLAN / SSID interfaces "
   "labelled with their Purdue level on the FW Topology Builder, as every placement check does; an unlabelled SSID "
   "is shown on the configuration evidence page but not flagged here. An SSID that no radio broadcasts (controller "
   "disabled, not assigned to an AP profile radio, no managed AP) is reported as informational dead configuration.",
   "Give OT wireless its own interface / VLAN and zone behind the firewall with policies into OT, use WPA2/WPA3-"
   "Enterprise (802.1X) with per-device credentials, enable PMF, and record the engineering justification; where "
   "the SSID is not needed in OT, re-bridge it to a non-OT VLAN or remove it.")
_e("config_link_monitor_external",
   "Every uplink link monitor probes a third-party public host (typically 8.8.8.8 / 8.8.4.4). If that host stops "
   "answering ICMP, the firewall declares its uplinks dead and withdraws their default routes - a design choice "
   "that ties the site's connectivity to a service it does not control.",
   "Probe the ISP gateways, or an internal anchor over the tunnel, alongside or instead of the public hosts; "
   "keep at least two independent targets per uplink.")
_e("config_auto_firmware_upgrade",
   "FortiGuard automatic firmware upgrades are enabled: the firewall replaces its own firmware when a release is "
   "published, a change to an OT boundary device outside the site's change control and maintenance windows, with "
   "the reboot and behaviour changes that brings.",
   "Disable auto-firmware-upgrade and apply firmware through change control (FortiManager or a planned upgrade in a "
   "maintenance window after testing); keep a scheduled window only where the site has accepted it in writing.")
_e("config_updates_from_internet",
   "Signature / firmware updates come directly from the internet, which requires internet egress "
   "from the OT boundary.",
   "Update from an internal FortiManager / update server.")
_e("zone_doc_1_1 zone_doc_1_2 zone_doc_1_3 zone_doc_1_4 zone_doc_1_5 zone_doc_1_6",
   "This control is a documentation / process requirement that the app cannot see in the data; "
   "without a current attestation there is no evidence it is met.",
   "Submit an attestation (Attestation page) with the supporting document.",
   "Closes with an attestation dated within the last 365 days.")

# family defaults (prefix) for anything not listed
FAMILY = [
    ("config_", "A FortiGate configuration setting deviates from the hardening baseline for OT "
                "boundary firewalls.", "Change the setting as described in the evidence (expected value)."),
    ("rule_", "A firewall rule permits traffic the OT zone model does not allow.",
              "Narrow or remove the rule."),
    ("chain_", "A chain of policies across several firewalls permits a path the zone model does not "
               "allow.", "Narrow or remove the policies in the chain."),
    ("session_", "Captured traffic shows a flow the zone model does not allow.",
                 "Stop the flow or approve and document it."),
    ("switch_", "A switch setting deviates from the hardening baseline.", "Change the switch setting."),
]

# checks of the periodic category whose review never closes them automatically
# (time-windowed items, partial evaluations, human-owned workflows - see
# alert_engine._AUTO_RESOLVE_CHECKS and the notes above it)
_NEVER_AUTO_CLOSED = frozenset({"denied_trend", "ntp_sync", "single_path_critical_device",
                                "no_path_redundancy_verified", "firmware_not_documented"})

_CLOSE_BY_CATEGORY = {
    "periodic_review": "Closes automatically on the next review run once the condition is gone. "
                       "Acknowledge it to accept the risk (it then stays visible as acknowledged).",
    "config_review": "Closes automatically when a configuration without the condition is uploaded. "
                     "Acknowledge it to accept the risk.",
    "real_time": "Raised from a log event: review it, then close or acknowledge it by hand.",
}

# evidence keys shown as facts (label), in this order; everything else stays raw
_FACTS = [
    ("device_name", "Device"), ("firewall", "Firewall"), ("vpn_policy_id", "VPN policy"),
    ("policy_id", "Policy"), ("policy_name", "Policy name"), ("interface", "Interface"),
    ("path_label", "Path"), ("allowed_by", "Allowed by"), ("service", "Service"),
    ("src_ip", "Source"), ("captured_src_ip", "Source as captured (before NAT attribution)"),
    ("dst_ip", "Destination"), ("captured_dst_ip", "Destination as captured (VIP)"),
    ("dst_port", "Port"), ("transport", "Transport"), ("protocol", "Protocol"),
    ("summary", "Operation"), ("occurrences", "Occurrences"),
    ("user_group", "VPN user group"), ("group_category", "Group category"),
    ("group_category_source", "Category decided by"),
    ("segment", "Segment"), ("l1_hosts", "Controllers"), ("l2_hosts", "L2 hosts"),
    ("exposure", "Reachable broadly by"), ("vip", "VIP"), ("external", "External address"),
    ("mapped", "Mapped address"), ("translated_to", "Translated to"),
    ("original_sources", "Original sources"), ("paths", "Paths"), ("sessions_unattributed", "Sessions arrived translated (no real source)"),
    ("sessions_attributed", "Sessions attributed from a pre-NAT capture"),
    ("username", "Account"), ("trusthost", "Trusted host"), ("ip", "IP"), ("mac", "MAC"),
    ("vendor", "Vendor"), ("user_groups", "VPN user groups"), ("tunnel_pool", "Tunnel pool"),
    ("portals", "Portals"), ("source_hidden_by_nat", "Source hidden by NAT"),
    ("reason", "Reason"), ("expected", "Expected"), ("current", "Current"),
]
_SKIP = {"description", "checklist_title", "access_path_tag", "access_path_tags", "chain_review",
         "chain", "path", "flags", "traffic", "nat", "classification", "paths_in_group",
         "severity_reason", "references", "fix"}
_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}


def _fmt(v) -> str:
    if isinstance(v, (list, tuple)):
        return ", ".join(_fmt(x) for x in v)
    if isinstance(v, dict):
        return ", ".join(f"{k}: {_fmt(x)}" for k, x in v.items())
    return "" if v is None else str(v)


def _same(a: Optional[str], b: Optional[str]) -> bool:
    norm = lambda x: "".join(ch for ch in str(x or "").lower() if ch.isalnum())[:24]
    return bool(a and b) and norm(a) == norm(b)


def _rows(checklist_id: Optional[str], own_title: Optional[str] = None) -> list:
    """Workbook row(s) of a finding.  ``title`` is the row as the app's check
    states it (the finding's checklist_title, else APP_TITLES, else the
    workbook); when the uploaded workbook's row says something else,
    ``workbook_title`` carries it and ``mismatch`` is True (the 62443 / NIST
    columns are then not attributed to the check)."""
    ids = [c.strip() for c in str(checklist_id or "").split(",") if c.strip()]
    out = []
    for i, cid in enumerate(ids):
        wb = ROWS.get(cid)
        app = (own_title if i == 0 else None) or APP_TITLES.get(cid)
        title = app or (wb or {}).get("title")
        row = {"id": cid, "title": title, "workbook_title": (wb or {}).get("title"),
               "mismatch": bool(app and wb and not _same(app, wb["title"])), "in_workbook": wb is not None}
        if wb and not row["mismatch"]:
            row.update({"section": wb["section"], "ref_62443": wb["ref_62443"], "nist": wb["nist"]})
        out.append(row)
    return out


def _seen(d: dict, title: str) -> bool:
    t = d.get("traffic") or {}
    return (isinstance(t, dict) and t.get("status") == "seen") or "[seen in capture]" in (title or "") \
        or "[matching traffic observed]" in (title or "") or bool(d.get("tunnel_sessions_in_capture"))


def _severity_reason(check, sev, default, d, title) -> str:
    if d.get("severity_reason"):
        return d["severity_reason"]
    if sev == default:
        return f"Default severity for this check ({default})."
    up = _ORDER.get(sev, 0) > _ORDER.get(default, 0)
    seen = _seen(d, title)
    if up and seen:
        return f"Raised from {default}: matching traffic was seen in the capture."
    if d.get("high_impact"):
        return f"Raised from {default}: a high-impact operation (program / stop / control)."
    if not up and d.get("bypass_kind") == "l2":
        return f"Lowered from {default}: the rule reaches the control zone (L2), not basic control (L0/L1)."
    if not up and d.get("dmz_source"):
        return f"Lowered from {default}: the source is the industrial DMZ, where jump hosts belong."
    if not up and not seen and check.startswith(("rule_", "chain_", "dmz_", "path_")):
        return f"Lowered from {default}: no matching traffic in the capture yet."
    return (f"{'Raised' if up else 'Lowered'} from the default ({default}) by the check's context "
            "- see What was found.")


def _what_text(f, d) -> str:
    if d.get("description"):
        return d["description"]
    parts = [f.title or ""]
    if d.get("reason"):
        parts.append(str(d["reason"]))
    if d.get("expected"):
        parts.append(f"Expected: {d['expected']}.")
    if d.get("nat_note"):
        parts.append(str(d["nat_note"]))
    return " ".join(p.rstrip(".") + "." for p in parts if p)


def _path(d) -> Optional[dict]:
    chain = d.get("chain") or []
    if not chain and not d.get("path"):
        return None
    p = d.get("path") or {}
    return {"src": p.get("src"), "dst": p.get("dst"), "direction": p.get("direction"),
            "hops": [{"firewall": c.get("firewall_name"), "policy_id": c.get("policy_id"),
                      "policy_name": c.get("policy_name")} for c in chain],
            "nat": d.get("nat") if isinstance(d.get("nat"), list) else [],
            "traffic": d.get("traffic") if isinstance(d.get("traffic"), dict) else None,
            "flags": d.get("flags") or []}


def entry(check: str) -> dict:
    e = C.get(check)
    if e:
        return e
    for pre, why, fix in FAMILY:
        if check.startswith(pre):
            return {"why": why, "fix": fix}
    return {"why": "The condition this check looks for was found; see What was found.",
            "fix": "Review the evidence and correct the configuration or traffic."}


def explain(f) -> dict:
    from app.models import CHECK_TYPE_REFERENCE
    from app import writeup as _wu
    d = f.detail if isinstance(f.detail, dict) else ({"description": f.detail} if f.detail else {})
    ref = CHECK_TYPE_REFERENCE.get(f.check_name)
    default = ref[2] if ref else f.severity
    category = f.category or (ref[3] if ref else None)
    e = entry(f.check_name or "")
    facts = []
    has_path = bool(d.get("chain"))
    for k, label in _FACTS:
        if has_path and k in ("path_label", "allowed_by"):
            continue          # shown as the hop list
        if not d.get("description") and k in ("reason", "expected"):
            continue          # already in the What-was-found text
        v = d.get(k)
        if v in (None, "", [], {}):
            continue
        facts.append([label, _fmt(v)])
    rows = _rows(f.checklist_id, d.get("checklist_title"))
    verify = next((ROWS[r["id"]]["verify"] for r in rows
                   if r["id"] in ROWS and not r["mismatch"] and ROWS[r["id"]].get("verify")), None)
    resolve = e["fix"]
    if d.get("fix") and d["fix"] not in resolve:
        resolve = f"{d['fix']} {resolve}"
    return {
        "check": f.check_name,
        "title": f.title,
        "what": {"text": _what_text(f, d), "facts": facts, "path": _path(d)},
        "why": e["why"],
        "requirement": {"sr": f.isa62443_sr, "rows": rows,
                        "references": d.get("references") if isinstance(d.get("references"), list) else None,
                        "standards": _wu.references(f.check_name or "", f.isa62443_sr)},   # owner 2026-10-17
        "concern": _wu.concern(f.check_name or "", e["why"]),
        "forti_example": _wu.forti_example(f.check_name or "", d),
        "severity": {"level": f.severity, "default": default,
                     "reason": _severity_reason(f.check_name or "", f.severity, default, d, f.title or "")},
        "resolve": resolve,
        "close": e.get("close") or (
            "Not closed automatically: acknowledge it to accept the risk, or close it by hand once the "
            "condition is gone." if f.check_name in _NEVER_AUTO_CLOSED else
            _CLOSE_BY_CATEGORY.get(category, _CLOSE_BY_CATEGORY["periodic_review"])),
        "verify": verify,
        "evidence": {k: v for k, v in d.items() if k not in _SKIP and k not in dict(_FACTS)},
    }
