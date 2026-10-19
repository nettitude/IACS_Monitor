"""
Per-check write-up for the report and the console (owner 2026-10-17):

* ``concern``   - one sentence: what was observed (generic, per check)
* ``why``       - why it is a finding (from app.explain)
* ``fix``       - remediation advice (from app.explain)
* ``references``- the standard / best-practice references: IEC 62443-3-3 SR
                  with its title, IEC 62443-2-1 / 3-2 where the check maps
                  there, NIST SP 800-82r3 with the SP 800-53 controls of the
                  foundational requirement, the CIS FortiGate Benchmark topic
                  for FortiGate configuration checks
* ``forti``     - a FortiOS CLI example that remediates the finding, filled
                  from the finding's evidence where it names a policy,
                  interface, account, ... (``<...>`` where it does not)
* ``closes``    - when the finding closes (from app.explain)

The report prints one write-up per check with every affected firewall /
subnet / host of the site under it; the SR / FR / SL / checklist numbers are
replaced by the references (owner's decision 2026-10-17).
"""
from __future__ import annotations

import re
from typing import Iterable, Optional

SR_TITLES = {
    "1.1": "Human user identification and authentication", "1.2": "Software process and device identification and authentication",
    "1.3": "Account management", "1.4": "Identifier management", "1.5": "Authenticator management",
    "1.6": "Wireless access management", "1.7": "Strength of password-based authentication",
    "1.8": "Public key infrastructure certificates", "1.9": "Strength of public key authentication",
    "1.10": "Authenticator feedback", "1.11": "Unsuccessful login attempts", "1.12": "System use notification",
    "1.13": "Access via untrusted networks", "2.1": "Authorization enforcement", "2.2": "Wireless use control",
    "2.3": "Use control for portable and mobile devices", "2.4": "Mobile code", "2.5": "Session lock",
    "2.6": "Remote session termination", "2.7": "Concurrent session control", "2.8": "Auditable events",
    "2.9": "Audit storage capacity", "2.10": "Response to audit processing failures", "2.11": "Timestamps",
    "2.12": "Non-repudiation", "3.1": "Communication integrity", "3.2": "Malicious code protection",
    "3.3": "Security functionality verification", "3.4": "Software and information integrity",
    "3.5": "Input validation", "3.6": "Deterministic output", "3.7": "Error handling", "3.8": "Session integrity",
    "3.9": "Protection of audit information", "4.1": "Information confidentiality", "4.2": "Information persistence",
    "4.3": "Use of cryptography", "5.1": "Network segmentation", "5.2": "Zone boundary protection",
    "5.3": "General purpose person-to-person communication restrictions", "5.4": "Application partitioning",
    "6.1": "Audit log accessibility", "6.2": "Continuous monitoring", "7.1": "Denial of service protection",
    "7.2": "Resource management", "7.3": "Control system backup", "7.4": "Control system recovery and reconstitution",
    "7.5": "Emergency power", "7.6": "Network and security configuration settings", "7.7": "Least functionality",
    "7.8": "Control system component inventory",
}
# NIST SP 800-53 controls per foundational requirement (the OT overlay of SP 800-82r3 maps these families)
NIST_BY_FR = {
    "1": "IA-2, IA-5, AC-7", "2": "AC-3, AC-6, AU-2", "3": "SI-3, SI-7", "4": "SC-8, SC-13",
    "5": "SC-7, AC-4", "6": "AU-6, SI-4", "7": "CM-7, CM-8, CP-9",
}
OTHER_62443 = {
    "2-1 NET 1.1": "IEC 62443-2-1 NET 1.1 (network segmentation and device inventory)",
    "2-1 NET 1.3": "IEC 62443-2-1 NET 1.3 (safety system isolation)",
    "2-1 NET 1.4": "IEC 62443-2-1 NET 1.4 (time synchronisation)",
    "2-1 NET 3.1": "IEC 62443-2-1 NET 3.1 (remote access)",
    "2-1 NET 3.2": "IEC 62443-2-1 NET 3.2 (vendor / temporary remote access)",
    "2-1 SPE 2": "IEC 62443-2-1 SPE 2 (configuration management of security settings)",
    "2-1 SPE 2 (CM)": "IEC 62443-2-1 SPE 2 (configuration management of security settings)",
    "ZCR 3": "IEC 62443 ZCR 3 (partition the system into zones and conduits)",
}
# CIS Fortinet FortiGate Benchmark topic per configuration check (topic names, not item numbers)
CIS = {
    "config_dns_external": "DNS server configuration", "config_default_hostname": "Hostname",
    "config_no_timezone": "Timezone", "config_ntp_fortiguard": "NTP time source", "config_ntp_unauthenticated": "NTP time source",
    "config_no_login_banner": "Pre-login banner", "config_no_password_policy": "Password policy", "config_weak_password_policy": "Password policy",
    "config_no_admin_lockout": "Administrator password retries and lockout time", "config_admin_lockout_threshold_high": "Administrator password retries and lockout time",
    "config_no_admin_idle_timeout": "Administrator idle timeout", "config_admin_idle_timeout_long": "Administrator idle timeout",
    "config_admin_no_trusted_hosts": "Trusted hosts on every administrator account", "config_admin_trusthost_too_broad": "Trusted hosts on every administrator account",
    "config_admin_trusthost_outside_mgmt": "Trusted hosts on every administrator account", "config_admin_profile_overprivileged": "Administrator profiles with least privilege",
    "config_admin_no_two_factor": "Two-factor authentication for administrators", "config_fortimanager_admin_access": "Central management (FortiManager)", "config_no_central_auth": "Centralised administrator authentication",
    "config_insecure_mgmt_protocol": "Encrypted management access only", "config_snmp_v1v2c_enabled": "SNMPv3 only", "config_snmp_default_community": "SNMP community strings",
    "config_strong_crypto_disabled": "Strong cryptography", "config_weak_tls_version": "TLS versions for administrative access", "config_sslvpn_weak_tls": "SSL-VPN TLS versions",
    "config_ha_no_auth": "High availability", "config_ha_no_monitor_interfaces": "HA monitor interfaces", "config_mgmt_not_restricted_to_mgmt_zone": "Management interface access",
    "config_logging_disabled": "Event logging", "config_no_syslog_forwarding": "Log transmission to a syslog server / FortiAnalyzer",
    "config_syslog_unencrypted": "Encrypted log transmission", "config_implicit_deny_not_logged": "Logging of denied traffic",
    "config_monitoring_readiness": "Logging on firewall policies", "config_remote_session_not_logged": "Logging on firewall policies",
    "config_permit_any_any_any": "Policies not using ALL as service", "config_policy_any_interface": "Policies bound to specific interfaces",
    "config_no_av_profile": "Antivirus security profile", "config_av_profile_not_applied": "Antivirus profile applied to policies",
    "config_av_missing_on_file_policy": "Antivirus profile applied to policies", "config_ids_ips_missing": "IPS security profile applied to policies",
    "config_updates_from_internet": "FortiGuard update source", "config_auto_firmware_upgrade": "Automatic firmware upgrade",
    "config_link_monitor_external": "Link monitoring targets",
    "switch_port_no_nac": "FortiSwitch port security (802.1X)", "switch_unused_port_enabled": "Unused switch ports", "config_usb_auto_install_config": "USB auto-install disabled",
    "config_usb_auto_install_image": "USB auto-install disabled", "config_maintainer_account_enabled": "Maintainer account",
    "config_maintainer_named_account": "Maintainer account", "config_no_revision_backup": "Configuration backups",
    "config_no_scheduled_backup": "Configuration backups", "config_unused_interface_not_disabled": "Unused interfaces disabled",
    "config_vpn_user_no_mfa": "Two-factor authentication for VPN users", "config_split_tunneling_enabled": "SSL-VPN split tunnelling",
    "config_weak_ipsec_crypto": "IPsec proposals", "config_ipsec_dialup_psk": "IPsec authentication", "config_ipsec_peer_unrestricted": "IPsec peer restriction",
    "config_wireless_weak_security": "Wireless security", "config_wireless_not_isolated": "Wireless network isolation", "config_wireless_in_ot": "Wireless network isolation",
    "config_device_detection_disabled": "Device detection", "config_rsp_check_disabled": "Reverse-path check (anti-spoofing)",
    "config_no_dos_policy_ot": "DoS policies", "config_fail_open_enabled": "Fail-open behaviour",
}
# the concern line where the first sentence of the "why" text is not a good one
CONCERN = {
    "config_admin_no_trusted_hosts": "Firewall administrator accounts accept logins from any source address.",
    "config_admin_trusthost_too_broad": "An administrator account's trusted hosts cover a very wide range.",
    "config_admin_trusthost_outside_mgmt": "An administrator account's trusted hosts lie outside the management networks.",
    "config_implicit_deny_not_logged": "Traffic that hits the implicit deny at the end of the policy table is not logged.",
    "rule_dns_external": "A policy lets hosts query an external DNS server (tcp / udp 53 to a public address or name).",
    "config_dns_external": "The firewall itself resolves names through an external DNS server.",
    "config_permit_any_any_any": "A policy permits any source to any destination on any service.",
    "config_insecure_mgmt_protocol": "Administrative access over HTTP or Telnet is enabled on an interface.",
    "config_no_syslog_forwarding": "The firewall keeps its logs locally only; nothing is forwarded to a collector.",
    "config_logging_disabled": "Event logging is disabled.",
    "config_vpn_direct_to_ot": "A VPN tunnel terminates directly in an OT zone.",
    "config_vpn_user_no_mfa": "A remote-access VPN user authenticates with a password only.",
    "config_admin_no_two_factor": "A local firewall administrator authenticates with a password only.",
    "config_fortimanager_admin_access": "The device is managed by FortiManager; administrative MFA depends on the FortiManager accounts.",
    "config_auto_firmware_upgrade": "The firewall upgrades its own firmware automatically from FortiGuard.",
    "config_link_monitor_external": "The uplink liveness checks probe third-party public hosts only.",
    "config_wireless_in_ot": "A wireless SSID lands in an OT network.",
    "switch_port_no_nac": "FortiSwitch access ports accept any device: no 802.1X / MAC-authentication policy is bound to them.",
    "switch_unused_port_enabled": "Enabled FortiSwitch access ports show no use.",
    "config_wireless_weak_security": "A wireless SSID uses weak security, or a pre-shared key inside an OT network.",
    "rule_it_ot_bypass": "A policy permits traffic from an IT zone straight into an OT zone, bypassing the DMZ.",
    "rule_mgmt_protocol": "A policy permits a management protocol (SSH, RDP, HTTPS admin, SNMP, ...) across a zone boundary from a non-management source.",
    "rule_cleartext_protocol": "A policy permits a cleartext protocol (Telnet, FTP, HTTP, SNMPv1/2c, ...) across a zone boundary.",
    "unused_policy": "A policy has not matched any traffic in the observation period.",
    "shadow_rule": "A policy can never match because an earlier policy covers it, or two policies contradict each other.",
}

# FortiOS CLI examples; {placeholders} are filled from the finding's evidence, "<name>" stays where unknown
FORTI = {
    "config_admin_no_trusted_hosts": 'config system admin\n    edit "{username}"\n        set trusthost1 {mgmt_net} 255.255.255.0      # management network\n        set trusthost2 {admin_host} 255.255.255.255   # admin workstation\n    next\nend',
    "config_admin_trusthost_too_broad": 'config system admin\n    edit "{username}"\n        set trusthost1 {mgmt_net} 255.255.255.0      # was {trusthost}\n    next\nend',
    "config_admin_trusthost_outside_mgmt": 'config system admin\n    edit "{username}"\n        set trusthost1 {mgmt_net} 255.255.255.0      # was {trusthost}\n    next\nend',
    "config_admin_no_two_factor": 'config system admin\n    edit "{username}"\n        set two-factor fortitoken\n        set fortitoken "<serial>"\n    next\nend',
    "config_admin_profile_overprivileged": 'config system accprofile\n    edit "ot-readonly"\n        set secfabgrp read\n        set ftviewgrp read\n        set authgrp read\n        set sysgrp read\n        set netgrp read\n        set loggrp read\n        set fwgrp read\n    next\nend\nconfig system admin\n    edit "{username}"\n        set accprofile "ot-readonly"      # was {profile}\n    next\nend',
    "config_admin_idle_timeout_long": 'config system global\n    set admintimeout 10        # minutes, was {value}\nend',
    "config_no_admin_idle_timeout": 'config system global\n    set admintimeout 10        # minutes\nend',
    "config_admin_lockout_threshold_high": 'config system global\n    set admin-lockout-threshold 3      # was {value}\n    set admin-lockout-duration 900\nend',
    "config_no_admin_lockout": 'config system global\n    set admin-lockout-threshold 3\n    set admin-lockout-duration 900\nend',
    "config_no_login_banner": 'config system global\n    set pre-login-banner enable\nend\nconfig system replacemsg admin "pre_admin-disclaimer-text"\n    set buffer "Authorised use only. Activity is monitored."\nend',
    "config_no_password_policy": 'config system password-policy\n    set status enable\n    set apply-to admin-password ipsec-preshared-key\n    set minimum-length 14\n    set min-lower-case-letter 1\n    set min-upper-case-letter 1\n    set min-non-alphanumeric 1\n    set min-number 1\n    set expire-status enable\n    set expire-day 90\n    set reuse-password disable\nend',
    "config_weak_password_policy": 'config system password-policy\n    set status enable\n    set minimum-length 14\n    set min-lower-case-letter 1\n    set min-upper-case-letter 1\n    set min-non-alphanumeric 1\n    set min-number 1\n    set reuse-password disable\nend',
    "config_no_central_auth": 'config user radius\n    edit "RADIUS-OT"\n        set server "{radius}"\n        set secret <secret>\n    next\nend\nconfig system admin\n    edit "{username}"\n        set remote-auth enable\n        set remote-group "RADIUS-OT"\n        set accprofile "prof_admin"\n    next\nend',
    "config_insecure_mgmt_protocol": 'config system interface\n    edit "{interface}"\n        set allowaccess ping https ssh      # was: {allowaccess}\n    next\nend\nconfig system global\n    set admin-https-redirect enable\nend',
    "config_mgmt_not_restricted_to_mgmt_zone": 'config system interface\n    edit "{interface}"\n        set allowaccess ping                 # no admin access on a non-management interface\n    next\n    edit "{mgmt_interface}"\n        set allowaccess ping https ssh\n        set dedicated-to management\n    next\nend',
    "config_local_in_permits_all": 'config firewall local-in-policy\n    edit {policy_id}\n        set intf "{interface}"\n        set srcaddr "MGMT-NET"              # was all\n        set dstaddr "all"\n        set service "HTTPS" "SSH"           # was ALL\n        set action accept\n    next\nend',
    "config_snmp_v1v2c_enabled": 'config system snmp community\n    delete {snmp_id}                         # v1 / v2c community "{community}"\nend\nconfig system snmp user\n    edit "ot-monitor"\n        set security-level auth-priv\n        set auth-proto sha256\n        set auth-pwd <password>\n        set priv-proto aes256\n        set priv-pwd <password>\n        set notify-hosts {collector}\n    next\nend',
    "config_snmp_default_community": 'config system snmp community\n    edit {snmp_id}\n        set name "<unique community>"         # was "{community}"\n        config hosts\n            edit 1\n                set ip {collector} 255.255.255.255\n            next\n        end\n    next\nend',
    "config_strong_crypto_disabled": 'config system global\n    set strong-crypto enable\nend',
    "config_weak_tls_version": 'config system global\n    set strong-crypto enable\n    set admin-https-ssl-versions tlsv1-2 tlsv1-3     # was {value}\nend',
    "config_sslvpn_weak_tls": 'config vpn ssl settings\n    set ssl-min-proto-ver tls1-2                  # was {value}\n    set algorithm high\nend',
    "config_ha_no_auth": 'config system ha\n    set group-name "{ha_group}"\n    set password <shared secret>\n    set authentication enable\n    set encryption enable\nend',
    "config_ha_no_monitor_interfaces": 'config system ha\n    set monitor "{interfaces}"\nend',
    "config_logging_disabled": 'config log eventfilter\n    set event enable\n    set system enable\n    set user enable\nend\nconfig log memory setting\n    set status enable\nend',
    "config_no_syslog_forwarding": 'config log syslogd setting\n    set status enable\n    set server "{collector}"\n    set mode reliable\n    set facility local7\nend',
    "config_syslog_unencrypted": 'config log syslogd setting\n    set status enable\n    set server "{collector}"\n    set mode reliable\n    set enc-algorithm high\n    set certificate "<client certificate>"\nend',
    "config_implicit_deny_not_logged": 'config log setting\n    set fwpolicy-implicit-log enable\nend\nconfig log syslogd setting\n    set status enable\n    set server "{collector}"\nend',
    "config_monitoring_readiness": 'config firewall policy\n    edit {policy_id}\n        set logtraffic all\n    next\nend\nconfig log setting\n    set fwpolicy-implicit-log enable\nend',
    "config_remote_session_not_logged": 'config firewall policy\n    edit {policy_id}                     # "{policy_name}"\n        set logtraffic all\n    next\nend',
    "config_permit_any_any_any": 'config firewall policy\n    edit {policy_id}                     # "{policy_name}": {src_zone} -> {dst_zone}\n        set srcaddr "<source hosts>"      # was all\n        set dstaddr "<destination hosts>" # was all\n        set service "<named services>"    # was ALL\n        set logtraffic all\n    next\nend',
    "config_policy_any_interface": 'config firewall policy\n    edit {policy_id}                     # "{policy_name}"\n        set srcintf "<source interface>"   # was any\n        set dstintf "<destination interface>"\n    next\nend',
    "config_overly_broad_subnet": 'config firewall address\n    edit "{object}"\n        set subnet <network> <mask>       # narrow to the hosts that need the rule\n    next\nend',
    "config_same_zone_rule": 'config firewall policy\n    delete {policy_id}                   # "{policy_name}" {src_zone} -> {dst_zone}: same zone, intra-zone traffic\nend\nconfig system zone\n    edit "{src_zone}"\n        set intrazone deny                # or allow if intra-zone traffic is intended\n    next\nend',
    "config_service_protocol_mismatch": 'config firewall service custom\n    edit "{service}"\n        set tcp-portrange <port>           # one port per protocol the name says\n    next\nend',
    "config_temporary_rule": 'config firewall policy\n    edit {policy_id}                     # "{policy_name}"\n        set schedule "<time-limited schedule>"\n        set comments "Temporary - owner, ticket, expiry date"\n    next\nend\n# or delete {policy_id} once the work is done',
    "config_vendor_rule_permanent": 'config firewall schedule onetime\n    edit "vendor-window"\n        set start 08:00 <date>\n        set end 17:00 <date>\n    next\nend\nconfig firewall policy\n    edit {policy_id}                     # "{policy_name}"\n        set schedule "vendor-window"\n        set status disable                # enable only for the window\n    next\nend',
    "config_rules_missing_owner": 'config firewall policy\n    edit {policy_id}                     # "{policy_name}"\n        set comments "Owner: <team> - Purpose: <why> - Reviewed: <date>"\n    next\nend',
    "config_vip_unused": 'config firewall vip\n    delete "{object}"                    # no policy references it\nend',
    "config_no_av_profile": 'config antivirus profile\n    edit "ot-av"\n        config http\n            set av-scan block\n        end\n        config smb\n            set av-scan block\n        end\n    next\nend',
    "config_av_profile_not_applied": 'config firewall policy\n    edit {policy_id}                     # "{policy_name}"\n        set utm-status enable\n        set av-profile "ot-av"\n        set ssl-ssh-profile "certificate-inspection"\n    next\nend',
    "config_av_missing_on_file_policy": 'config firewall policy\n    edit {policy_id}                     # "{policy_name}": file transfer into OT\n        set utm-status enable\n        set av-profile "ot-av"\n    next\nend',
    "config_ids_ips_missing": 'config ips sensor\n    edit "ot-ips"\n        config entries\n            edit 1\n                set severity high critical\n                set status enable\n                set action block\n            next\n        end\n    next\nend\nconfig firewall policy\n    edit {policy_id}                     # "{policy_name}": into OT\n        set utm-status enable\n        set ips-sensor "ot-ips"\n    next\nend',
    "config_industrial_dpi_missing": 'config application list\n    edit "ot-industrial"\n        config entries\n            edit 1\n                set category 30            # Industrial\n                set action pass\n                set log enable\n            next\n        end\n    next\nend\nconfig firewall policy\n    edit {policy_id}                     # "{policy_name}": industrial protocol into OT\n        set utm-status enable\n        set application-list "ot-industrial"\n    next\nend',
    "config_ntp_fortiguard": 'config system ntp\n    set ntpsync enable\n    set type custom\n    config ntpserver\n        edit 1\n            set server "{ntp}"           # the internal source; remove the public pools\n            set authentication enable\n            set key-type SHA1\n            set key <key>\n            set key-id 1\n        next\n    end\n    set server-mode enable             # OT interfaces keep taking time from this firewall\nend',
    "config_ntp_unauthenticated": 'config system ntp\n    set type custom\n    config ntpserver\n        edit 1\n            set server "{ntp}"\n            set authentication enable\n            set key-type SHA1\n            set key <key>\n            set key-id 1\n        next\n    end\nend',
    "config_no_timezone": 'config system global\n    set timezone "<your zone>"\nend',
    "config_default_hostname": 'config system global\n    set hostname "<site>-<role>-<n>"      # was {hostname}\nend',
    "config_dns_external": 'config system dns\n    set primary {dns_internal}\n    set secondary <internal resolver 2>\n    unset protocol                        # was: {servers}\nend',
    "switch_port_no_nac": 'config switch-controller security-policy 802-1X\n    edit "ot-nac"\n        set user-group "<RADIUS user group>"\n        set mac-auth-bypass enable       # only for devices that cannot do 802.1X\n        set open-auth disable\n        set eap-passthru enable\n    next\nend\nconfig switch-controller managed-switch\n    edit "{switch_device}"\n        config ports\n            edit "{port}"\n                set port-security-policy "ot-nac"\n            next\n        end\n    next\nend',
    "switch_unused_port_enabled": 'config switch-controller managed-switch\n    edit "{switch_device}"\n        config ports\n            edit "{port}"\n                set status down\n                set description "reserved - <purpose>"\n            next\n        end\n    next\nend',
    "config_link_monitor_external": 'config system link-monitor\n    edit "wan1_monitor"\n        set srcintf "wan1"\n        set server "<ISP gateway>" "8.8.8.8"     # an ISP-side target next to the public one\n        set interval 1000\n        set failtime 3\n        set recoverytime 2\n    next\nend',
    "config_auto_firmware_upgrade": 'config system fortiguard\n    set auto-firmware-upgrade disable      # was enable (window {upgrade_window})\nend',
    "config_updates_from_internet": 'config system central-management\n    set type fortimanager\n    set fmg "<FortiManager in the DMZ>"\n    set include-default-servers disable\n    config server-list\n        edit 1\n            set server-type update rating\n            set server-address <FortiManager>\n        next\n    end\nend',
    "config_usb_auto_install_config": 'config system auto-install\n    set auto-install-config disable\nend',
    "config_usb_auto_install_image": 'config system auto-install\n    set auto-install-image disable\nend',
    "config_maintainer_account_enabled": 'config system global\n    set admin-maintainer disable\nend',
    "config_maintainer_named_account": 'config system admin\n    delete "{username}"                   # "maintainer" is a vendor recovery name\nend\nconfig system global\n    set admin-maintainer disable\nend',
    "config_no_revision_backup": 'config system global\n    set revision-backup-on-logout enable\n    set revision-image-auto-backup enable\nend',
    "config_no_scheduled_backup": 'config system auto-script\n    edit "weekly-backup"\n        set interval 604800\n        set repeat 0\n        set script "execute backup config sftp <path> <host> <user> <pass>"\n    next\nend',
    "config_unused_interface_not_disabled": 'config system interface\n    edit "{interface}"\n        set status down\n    next\nend',
    "config_no_internal_segmentation": 'config system interface\n    edit "<control-net>"\n        set vdom "root"\n        set ip <gateway> 255.255.255.0\n        set role lan\n    next\nend\n# one interface / VLAN per Purdue level, policies between them',
    "config_possible_dual_homed": 'config firewall policy\n    edit {policy_id}                     # the IT and OT leg both reach "{object}"\n        set dstaddr "<OT hosts>"            # keep one leg; the other goes through the DMZ\n    next\nend',
    "config_broadcast_cross_zone": 'config system interface\n    edit "{interface}"\n        set broadcast-forward disable\n    next\nend',
    "config_icmp_across_boundary": 'config firewall policy\n    edit {policy_id}                     # "{policy_name}": {src_zone} -> {dst_zone}\n        set service "PING"                 # ICMP echo only, was {service}\n        set srcaddr "<monitoring hosts>"\n    next\nend',
    "config_email_web_to_ot": 'config firewall policy\n    edit {policy_id}                     # "{policy_name}" permits e-mail / web into OT\n        set service "<industrial services only>"   # was {service}\n    next\nend',
    "config_fail_open_enabled": 'config ips global\n    set fail-open disable\nend\nconfig system npu\n    set fail-open disable\nend',
    "config_rsp_check_disabled": 'config system settings\n    set strict-src-check enable\n    set asymroute disable\nend',
    "config_no_dos_policy_ot": 'config firewall DoS-policy\n    edit 1\n        set interface "{interface}"\n        set srcaddr "all"\n        set dstaddr "all"\n        set service "ALL"\n        config anomaly\n            edit "tcp_syn_flood"\n                set status enable\n                set log enable\n                set action block\n                set threshold 2000\n            next\n            edit "ip_src_session"\n                set status enable\n                set action block\n                set threshold 5000\n            next\n        end\n    next\nend',
    "config_device_detection_disabled": 'config system interface\n    edit "{interface}"\n        set device-identification enable\n    next\nend',
    "config_vpn_direct_to_ot": 'config firewall policy\n    edit {policy_id}                     # "{policy_name}": VPN -> {dst_zone}\n        set dstintf "<DMZ jump host interface>"   # was {dst_zone}\n        set dstaddr "<jump host>"\n        set service "RDP" "SSH"\n    next\nend',
    "config_vpn_destination_unclear": 'config firewall policy\n    edit {policy_id}                     # "{policy_name}"\n        set dstaddr "<jump host>"            # was {dst}\n        set service "<named services>"\n    next\nend',
    "config_vpn_no_routing_policy": 'config firewall policy\n    edit <new>\n        set srcintf "{interface}"\n        set dstintf "<DMZ interface>"\n        set srcaddr "SSLVPN_TUNNEL_ADDR1"\n        set dstaddr "<jump host>"\n        set service "RDP" "SSH"\n        set action accept\n        set logtraffic all\n    next\nend',
    "config_vpn_source_unrestricted": 'config firewall policy\n    edit {policy_id}                     # "{policy_name}"\n        set srcaddr "SSLVPN_TUNNEL_ADDR1"   # was all\n        set groups "{group}"\n    next\nend',
    "config_vpn_shared_access": 'config user local\n    edit "<person>"\n        set type password\n        set passwd <password>\n        set two-factor fortitoken\n    next\nend\n# one account per person; retire the shared account "{username}"',
    "config_vpn_user_no_mfa": 'config user local\n    edit "{username}"\n        set two-factor fortitoken\n        set fortitoken "<serial>"\n    next\nend\n# LDAP-mapped users: the same two-factor setting on the local user of type ldap;\n# or move the group to a RADIUS / TACACS+ server that enforces MFA',
    "config_fortimanager_admin_access": '# on the FortiManager, not on this device:\nconfig system admin user\n    edit "<fortimanager admin>"\n        set two-factor-auth enable\n        set fortitoken "<serial>"\n    next\nend\n# on this device, keep the tunnel on the management network only:\nconfig system central-management\n    set type fortimanager\n    set fmg "{fortimanager}"\n    set fmg-source-ip <management interface address>\nend',
    "config_vpn_no_idle_timeout": 'config vpn ssl settings\n    set idle-timeout 900\n    set auth-timeout 28800\nend',
    "config_vpn_idle_timeout_long": 'config vpn ssl settings\n    set idle-timeout 900                 # seconds, was {value}\nend',
    "config_split_tunneling_enabled": 'config vpn ssl web portal\n    edit "{portal}"\n        set split-tunneling disable\n    next\nend',
    "config_weak_ipsec_crypto": 'config vpn ipsec phase1-interface\n    edit "{tunnel}"\n        set ike-version 2\n        set proposal aes256-sha256 aes256gcm-prfsha384\n        set dhgrp 19 20\n    next\nend\nconfig vpn ipsec phase2-interface\n    edit "{tunnel}"\n        set proposal aes256-sha256 aes256gcm\n        set pfs enable\n        set dhgrp 19 20\n    next\nend',
    "config_ipsec_dialup_psk": 'config vpn ipsec phase1-interface\n    edit "{tunnel}"\n        set authmethod signature\n        set certificate "<device certificate>"\n        set peertype peergrp\n        set peergrp "<allowed peers>"\n    next\nend',
    "config_ipsec_peer_unrestricted": 'config vpn ipsec phase1-interface\n    edit "{tunnel}"\n        set remote-gw <peer address>        # was: any\n        set peertype one\n        set peerid "<peer id>"\n    next\nend',
    "config_wireless_weak_security": 'config wireless-controller vap\n    edit "{vap}"\n        set security wpa2-only-enterprise      # was {security}; 802.1X with per-device credentials\n        set auth radius\n        set radius-server "<RADIUS / NPS>"\n        set pmf enable\n    next\nend',
    "config_wireless_in_ot": 'config wireless-controller vap\n    edit "{vap}"\n        set local-bridging enable\n        set vlanid <wireless VLAN>              # was {vlan_id}: its own VLAN, not an OT one\n        set security wpa2-only-enterprise\n        set pmf enable\n    next\nend\nconfig system interface\n    edit "<wireless VLAN interface>"\n        set vlanid <wireless VLAN>\n        set interface "<trunk port>"\n        set role lan\n    next\nend\n# then policies from the wireless zone into OT for the named devices and services only',
    "config_wireless_not_isolated": 'config wireless-controller vap\n    edit "{vap}"\n        set intra-vap-privacy enable\n        set vlanid <wireless VLAN>          # its own VLAN, policies into OT only via the DMZ\n    next\nend',
    "rule_dns_external": 'config firewall address\n    edit "DNS-internal"\n        set subnet {dns_internal} 255.255.255.255\n    next\nend\nconfig firewall policy\n    edit {policy_id}                     # "{policy_name}"\n        set srcintf "{src_zone}"\n        set dstintf "<internal resolver interface>"   # was {dst_zone}\n        set dstaddr "DNS-internal"          # was {dst}\n        set service "DNS"\n        set action accept\n    next\nend',
    "rule_it_ot_bypass": 'config firewall policy\n    edit {policy_id}                     # "{policy_name}": {src_zone} -> {dst_zone}\n        set dstintf "<DMZ interface>"       # terminate in the DMZ, was {dst_zone}\n        set dstaddr "<DMZ relay / jump host>"\n        set service "{service}"\n        set logtraffic all\n    next\nend',
    "rule_mgmt_protocol": 'config firewall policy\n    edit {policy_id}                     # "{policy_name}"\n        set srcaddr "<admin / jump hosts>"   # was {src}\n        set service "{service}"\n        set logtraffic all\n    next\nend',
    "rule_mgmt_wrong_zone": 'config firewall policy\n    edit {policy_id}                     # "{policy_name}"\n        set srcintf "<management interface>"   # was {src_zone}\n        set srcaddr "<admin / jump hosts>"\n    next\nend',
    "rule_cleartext_protocol": 'config firewall policy\n    edit {policy_id}                     # "{policy_name}"\n        set service "SSH"                    # encrypted replacement for {service}\n    next\nend',
    "rule_cleartext_creds": 'config firewall policy\n    edit {policy_id}                     # "{policy_name}"\n        set service "<encrypted service>"    # was {service}\n    next\nend',
    "rule_implicit_permit": 'config firewall policy\n    edit {policy_id}                     # "{policy_name}"\n        set srcaddr "<named sources>"       # was {src}\n        set dstaddr "<named destinations>"  # was {dst}\n        set service "<named services>"      # was {service}\n    next\nend',
    "rule_ot_it_dependency": 'config firewall policy\n    edit {policy_id}                     # "{policy_name}": OT depends on {dst}\n        set dstaddr "<DMZ replica / relay>"   # host the service in the DMZ\n    next\nend',
    "rule_conduit_drift": 'config firewall policy\n    edit {policy_id}                     # "{policy_name}"\n        set service "<services of the documented conduit>"   # was {service}\n    next\nend',
    "unused_policy": 'config firewall policy\n    edit {policy_id}                     # "{policy_name}": no match since {last_matched}\n        set status disable                # delete after the review period\n    next\nend',
    "disabled_rule": 'config firewall policy\n    delete {policy_id}                   # "{policy_name}": disabled, remove or document\nend',
    "shadow_rule": 'config firewall policy\n    delete {policy_id_b}                 # shadowed by policy {policy_id_a}\nend',
    "fqdn_in_policy": 'config firewall address\n    edit "{object}"\n        set type ipmask\n        set subnet <address> 255.255.255.255   # was fqdn {fqdn_value}\n    next\nend',
}

# evidence keys that fill the placeholders (first non-empty wins)
_FILL = {
    "username": ("username", "user", "admin", "name"), "policy_id": ("policy_id", "vpn_policy_id"), "policy_name": ("policy_name",),
    "src_zone": ("src_zone", "srcintf", "src_intf", "zone", "interface"), "dst_zone": ("dst_zone", "dstintf", "dst_intf", "zone"),
    "interface": ("interface", "ot_interfaces_without_dos_policy", "src_zone", "ot_interface"), "mgmt_interface": ("mgmt_interface",), "service": ("service", "dst_port", "services"),
    "src": ("src", "srcaddr"), "dst": ("dst", "dstaddr", "destination"), "object": ("object", "vip", "address", "addresses", "name"),
    "value": ("value", "current", "setting", "idle_timeout_seconds", "timeout", "threshold", "versions"), "security": ("security",), "vlan_id": ("vlan_id", "vlanid"), "trusthost": ("trusthost", "trusthosts"),
    "profile": ("profile", "accprofile"), "allowaccess": ("allowaccess", "protocols", "insecure"), "snmp_id": ("snmp_id", "id"),
    "community": ("community",), "collector": ("collector", "syslog_server", "server"), "ha_group": ("ha_group", "group_name"),
    "interfaces": ("interfaces", "monitor"), "ntp": ("ntp", "local_servers", "server"), "hostname": ("hostname",), "servers": ("servers", "resolvers"),
    "group": ("group", "groups"), "portal": ("portal", "portals"), "tunnel": ("tunnel", "phase1", "name"), "vap": ("vap", "ssid", "interface", "name"),
    "last_matched": ("last_matched",), "policy_id_a": ("policy_id_a",), "policy_id_b": ("policy_id_b",), "fqdn_value": ("fqdn_value",),
    "dns_internal": ("dns_internal",), "mgmt_net": ("mgmt_net",), "admin_host": ("admin_host",), "radius": ("radius",),
    "fortimanager": ("fortimanager", "fmg"), "upgrade_window": ("upgrade_window",),
    "switch_device": ("switch_device",), "port": ("first_port", "port"),
}
_DEFAULTS = {
    "username": "<admin account>", "policy_id": "<policy id>", "policy_name": "<policy>", "src_zone": "<source interface>",
    "dst_zone": "<destination interface>", "interface": "<interface>", "mgmt_interface": "<management interface>", "service": "<service>",
    "src": "<source>", "dst": "<destination>", "object": "<object>", "value": "<current value>", "trusthost": "<current trusted hosts>",
    "profile": "<profile>", "allowaccess": "<current protocols>", "snmp_id": "<community id>", "community": "<community>",
    "collector": "<syslog collector>", "ha_group": "<HA group>", "interfaces": "<interfaces>", "ntp": "<internal NTP server>",
    "hostname": "<current hostname>", "servers": "<current resolvers>", "group": "<VPN group>", "portal": "<portal>", "tunnel": "<tunnel>",
    "vap": "<SSID>", "last_matched": "<date>", "policy_id_a": "<earlier policy>", "policy_id_b": "<shadowed policy>", "fqdn_value": "<fqdn>",
    "dns_internal": "<internal resolver>", "mgmt_net": "<management network>", "admin_host": "<admin workstation>", "radius": "<RADIUS server>",
    "fortimanager": "<FortiManager address>", "upgrade_window": "", "switch_device": "<switch>", "port": "<port>", "security": "<current security>", "vlan_id": "<VLAN>",
}


def _first(d: dict, keys: Iterable[str]):
    for k in keys:
        v = d.get(k)
        if v in (None, "", [], {}):
            continue
        if isinstance(v, (list, tuple)):
            v = ", ".join(str(x) for x in v[:4])
        elif isinstance(v, dict):
            continue
        return str(v)
    return None


def forti_example(check: str, detail: Optional[dict] = None) -> Optional[str]:
    """The FortiOS example for ``check`` filled from ``detail`` (a finding's
    evidence); None when the check has no FortiOS remediation."""
    tpl = FORTI.get(check)
    if not tpl:
        return None
    d = detail if isinstance(detail, dict) else {}
    values = {}
    for ph, keys in _FILL.items():
        v = _first(d, keys)
        if v and ph in ("src_zone", "dst_zone", "interfaces", "interface") and "," in v:
            parts = [t.strip() for t in v.split(",") if t.strip()]
            # several interfaces: `"a" "b"` where the template quotes the placeholder, `a, b` in comments
            tpl = tpl.replace('"{' + ph + '}"', '"{' + ph + '__q}"')
            values[ph + "__q"] = '" "'.join(parts)
            v = ", ".join(parts)
        values[ph] = v or _DEFAULTS[ph]
    try:
        return tpl.format(**values)
    except (KeyError, IndexError, ValueError):
        return FORTI[check]


def references(check: str, sr_text: Optional[str]) -> list:
    """The standard / best-practice references of a check, in print order."""
    out, frs = [], []
    for tok in (sr_text or "").split(","):
        tok = tok.strip()
        if not tok:
            continue
        m = re.match(r"^SR\s+(\d)\.(\d+)(?:\s*RE\s*(\d))?$", tok)
        if m:
            key = f"{m.group(1)}.{m.group(2)}"
            title = SR_TITLES.get(key, "")
            re_txt = f" RE {m.group(3)}" if m.group(3) else ""
            out.append(f"IEC 62443-3-3 SR {key}{re_txt}" + (f" ({title})" if title else ""))
            if m.group(1) not in frs:
                frs.append(m.group(1))
        elif tok in OTHER_62443:
            out.append(OTHER_62443[tok])
        else:
            out.append(f"IEC 62443 {tok}")
    if frs:
        out.append("NIST SP 800-82r3 (OT overlay of SP 800-53: " + "; ".join(NIST_BY_FR[f] for f in frs if f in NIST_BY_FR) + ")")
    if check in CIS:
        out.append(f"CIS Fortinet FortiGate Benchmark - {CIS[check]}")
    if check.startswith(("zone_doc_", "undocumented_conduit", "conduit_")) and not any("zone and conduit" in r for r in out):
        out.append("IEC 62443 (zone and conduit design)")
    return out


def concern(check: str, why: str) -> str:
    if check in CONCERN:
        return CONCERN[check]
    first = re.split(r"(?<=\.)\s", (why or "").strip(), 1)[0].rstrip(";:, ")
    return (first + ("" if first.endswith(".") else ".")) if first else "The condition this check looks for was found."


def writeup(check: str, sr_text: Optional[str], detail: Optional[dict] = None) -> dict:
    """concern / why / fix / references / forti / closes for one check,
    the FortiOS example filled from ``detail`` (typically the first finding)."""
    from app.explain import entry, _CLOSE_BY_CATEGORY, _NEVER_AUTO_CLOSED
    from app.models import CHECK_TYPE_REFERENCE
    e = entry(check)
    ref = CHECK_TYPE_REFERENCE.get(check)
    cat = ref[3] if ref else "periodic_review"
    closes = e.get("close") or ("Not closed automatically: acknowledge it to accept the risk, or close it by hand once the condition is gone."
                                if check in _NEVER_AUTO_CLOSED else _CLOSE_BY_CATEGORY.get(cat, _CLOSE_BY_CATEGORY["periodic_review"]))
    return {"check": check, "concern": concern(check, e.get("why", "")), "why": e.get("why", ""), "fix": e.get("fix", ""),
            "references": references(check, sr_text or (ref[0] if ref else "")), "forti": forti_example(check, detail), "closes": closes}
