"""Owner (2026-10-11): `rule_dns_external` - any enabled permit policy that lets
hosts query an external DNS server (tcp / udp 53 to a public address, name or
internet-service object) - and `config_dns_external` naming every external
resolver of the firewall itself (FortiGuard DNS when none is configured).

The site mirrors the owner's policy 306 "DNS_Services": five VLANs -> wan1 /
wan2, two OT hosts to 8.8.8.8 and 8.8.4.4 over tcp/udp 53 and ICMP."""
import textwrap

from app.models import Finding, FirewallRule
from app.parsers import alert_engine as ae
from app.parsers.alert_engine import review_rule_dns_external
from app.parsers.forti_config_parser import (_config_findings, _extract_dns_ntp, _extract_vpn_settings,
                                             flatten_global_vdom, parse_forti_block, sanitize_forti_tree)
from tests.test_access_paths import _ingest, _site, db  # noqa: F401  (db fixture)

CFG = """
config system interface
    edit "wan1"
        set vdom "root"
        set ip 203.0.113.2 255.255.255.252
    next
    edit "wan2"
        set vdom "root"
        set ip 198.51.100.2 255.255.255.252
    next
    edit "vlan_20"
        set vdom "root"
        set ip 10.168.20.1 255.255.255.0
    next
    edit "vlan_22"
        set vdom "root"
        set ip 10.168.22.1 255.255.255.0
    next
    edit "vlan_101"
        set vdom "root"
        set ip 10.168.101.1 255.255.255.0
    next
end
config firewall address
    edit "hmi-20"
        set subnet 10.168.20.20 255.255.255.255
    next
    edit "hmi-22"
        set subnet 10.168.22.20 255.255.255.255
    next
    edit "office"
        set subnet 10.168.101.0 255.255.255.0
    next
    edit "google-a"
        set subnet 8.8.8.8 255.255.255.255
    next
    edit "google-b"
        set subnet 8.8.4.4 255.255.255.255
    next
    edit "internal-dns"
        set subnet 10.168.32.53 255.255.255.255
    next
end
config firewall addrgrp
    edit "HMIs"
        set member "hmi-20" "hmi-22"
    next
    edit "GoogleDNS"
        set member "google-a" "google-b"
    next
end
config firewall service custom
    edit "DNS_ALL"
        set tcp-portrange 53
        set udp-portrange 53
    next
end
config firewall policy
    edit 306
        set name "DNS_Services"
        set srcintf "vlan_20" "vlan_22" "vlan_101"
        set dstintf "wan1" "wan2"
        set srcaddr "HMIs"
        set dstaddr "GoogleDNS"
        set action accept
        set schedule "always"
        set service "DNS_ALL" "PING"
    next
    edit 307
        set name "Office_DNS"
        set srcintf "vlan_101"
        set dstintf "wan1"
        set srcaddr "office"
        set dstaddr "google-a"
        set action accept
        set schedule "always"
        set service "DNS"
    next
    edit 308
        set name "Internal_DNS"
        set srcintf "vlan_20"
        set dstintf "vlan_101"
        set srcaddr "HMIs"
        set dstaddr "internal-dns"
        set action accept
        set schedule "always"
        set service "DNS"
    next
    edit 309
        set name "Web"
        set srcintf "vlan_101"
        set dstintf "wan1"
        set srcaddr "office"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "HTTPS"
    next
end
"""


def _findings(db, sid):
    with ae.analysis_site(db, sid):
        review_rule_dns_external(db)
    db.commit()
    return {f.detail["policy_id"]: f for f in db.query(Finding).filter(Finding.check_name == "rule_dns_external")}


def test_external_dns_policy_is_one_finding_per_policy(db):
    sid = _site(db, "LPS")
    _ingest(db, CFG, "site-a-rout01", sid, {"wan1": 5, "wan2": 5, "vlan_20": 2, "vlan_22": 2, "vlan_101": 4})
    rows = db.query(FirewallRule).filter(FirewallRule.policy_id == "306").all()
    assert len(rows) >= 8                                   # 2 src x 2 dst x (tcp, udp, icmp)
    found = _findings(db, sid)
    assert set(found) == {"306", "307"}                     # internal DNS (308) and dst all (309) are not
    f = found["306"]
    assert f.severity == "high"                             # OT source (L2)
    assert sorted(f.detail["external_destinations"]) == ["8.8.4.4/32", "8.8.8.8/32"]
    assert f.detail["transports"] == ["tcp", "udp"]         # the ICMP rows are not DNS
    assert f.detail["expanded_rows"] == 8
    assert "8.8.8.8/32" in f.title and "DNS_Services" in f.title or "306" in f.title
    assert "OT zone" in f.detail["description"] and "high" in f.detail["severity_reason"]
    assert found["307"].severity == "low"                   # enterprise source only
    # a second run neither duplicates nor re-raises
    _findings(db, sid)
    assert db.query(Finding).filter(Finding.check_name == "rule_dns_external").count() == 2


def test_unknown_level_and_fqdn_destinations(db):
    sid = _site(db, "LPS")
    cfg = CFG.replace('set dstaddr "google-a"', 'set dstaddr "fqdn:dns.google"').replace(
        '    edit "google-a"\n        set subnet 8.8.8.8 255.255.255.255\n    next\n',
        '    edit "google-a"\n        set subnet 8.8.8.8 255.255.255.255\n    next\n    edit "fqdn:dns.google"\n        set type fqdn\n        set fqdn "dns.google"\n    next\n')
    _ingest(db, cfg, "fw", sid, {})                         # no interface levels at all
    found = _findings(db, sid)
    assert found["306"].severity == "medium"                # level unknown
    assert "unknown" in found["306"].detail["severity_reason"]
    assert found["307"].detail["external_destinations"] == ["fqdn:dns.google"]


def test_config_dns_external_names_every_external_resolver():
    base = textwrap.dedent("""
    config system global
        set hostname "fw"
    end
    config system interface
        edit "port1"
            set ip 10.0.0.1 255.255.255.0
        next
    end
    """)
    def run(dns_block):
        parsed = sanitize_forti_tree(flatten_global_vdom(parse_forti_block(base + dns_block), quiet=True), {})
        dns_ntp = _extract_dns_ntp(parsed)
        f = [x for x in _config_findings([], {}, _extract_vpn_settings(parsed), dns_ntp, "fw")
             if x["check_name"] == "config_dns_external"]
        return f[0] if f else None
    # both external: both named
    f = run('config system dns\n    set primary 8.8.8.8\n    set secondary 1.1.1.1\nend\n')
    assert f and f["detail"]["external_resolvers"] == ["8.8.8.8", "1.1.1.1"] and "secondary 1.1.1.1" in f["title"]
    # internal primary, external secondary: still a finding, naming only the external one
    f = run('config system dns\n    set primary 10.0.0.53\n    set secondary 9.9.9.9\nend\n')
    assert f and f["detail"]["external_resolvers"] == ["9.9.9.9"] and f["detail"]["fortiguard_default"] is False
    # nothing configured = FortiOS default = FortiGuard DNS
    f = run('')
    assert f and f["detail"]["fortiguard_default"] is True and "FortiGuard" in f["title"]
    assert f["detail"]["external_resolvers"] == ["96.45.45.45", "96.45.46.46"]
    # both internal: nothing
    assert run('config system dns\n    set primary 10.0.0.53\n    set secondary 10.0.0.54\nend\n') is None
