"""
Seed a throwaway demo database and serve the app, for manual / Playwright UI
checks. NOT a pytest module (no test_ prefix).

    python tests/ui_demo_server.py --db /tmp/ui_demo.db --port 8765 [--no-serve]

Loads every sample in sample_data/ through the real API (same code paths the
UI uses), assigns Purdue levels, runs periodic reviews, adds attestations,
and plants XSS payloads in fields that come from ingested/untrusted data
(device names from syslog devname= and the multi-vendor syslog device_name
fallback, a NAT rule (VIP) name, asset-inventory device_type, hostnames,
attestation text, proof filename). It also uploads the three multi-vendor
syslog samples through /ingest/syslog, stamps a rule hit (last_matched),
adds a DNAT + SNAT rule on FW-OT and marks one host stale.

Multi-site (phase 1): two sites are created, "Plant A" (code plant-a: the
FortiGate FW-OT, switches, MAC/ARP tables, the PCAP, baseline B1 and the
attestation) and "Plant B" (code plant-b: the Cisco and pfSense firewalls
and the Unix ARP table).

Multi-site (phase 2, isolation): Plant B ALSO gets the very same FortiGate
config (firewall "FW-OT"), the Cisco ARP table and the PCAP - i.e. the two
sites have OVERLAPPING IPs, MACs and a firewall of the same name.  Sites are
isolated, so each site has its own hosts, firewall rows and findings (the
seed prints the per-site counts and asserts the overlap really produced two
independent row sets).  Reviews run once per site.

Multi-site (phase 3, log routing): log uploads are routed per device.  The
FortiGate logs are uploaded with site=plant-a (their devices - FGT-CORE,
FW-OT and the XSS-named devname - get mapped to Plant A), the multi-vendor
samples with site=plant-b (asa-fw01, pfsense, the PAN-OS device and the
XSS fallback name -> Plant B).  Finally routing_demo.log (no site) holds a
line from the KNOWN asa-fw01 (routed to Plant B) and one from the unknown
"rogue-fw9", so the console's "Unmapped devices" list is non-empty.
B-11: two conflicts are held for the console's "Conflicts" list - a serial
conflict (fgt-edge-a registered at Plant A with serial FGT60F0000000001, a
line from it carrying FGT60F0000009999) and a site mismatch (a Plant A upload
with a line from asa-fw01, which is registered to Plant B).
B-12: FG-OT-PERIMETER-01 (Plant A, from the sample config's "config system
ha": a-p, group OT-FW-HA) is an HA cluster: a log file with traffic from two
member serials and one HA "member joined" event from the first unit naming
the second makes the registry list both serials as members (the second one
added from the HA event log) - the Devices page shows the HA badge and the
member list (the a-p failover from unit 1 to unit 2 also raises one low
"HA failover detected" finding in Plant A).
Multi-site (phase 4): nothing extra is seeded - the console's "Sites overview"
roll-up is derived from the per-site data above (Plant A / Plant B severity
counts, uploads, attestation; no Default site - FI-01) and the smoke test checks it
against GET /sites/rollup.
Access Review (access-path review phase 3 UI): FW-OT's config yields flagged
access paths in Plant A; seed_access_review() adds two captured sessions (one
makes a path "Seen in capture", one is an unexplained flow no rule allows)
and classifies a path (Reviewed OK + note) and the flow (Permissive, with an
XSS payload in the note / classified_by) via POST /access-paths/classify.
A page that renders any of them unescaped
will create `window.__xss` / an <img data-xss> element - checks look for that.
"""
import argparse
import os
import subprocess
import sys
import tempfile
from datetime import datetime, timedelta, timezone
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
SAMPLES = ROOT / "sample_data"
XSS = '<img src=x data-xss=1 onerror="window.__xss=(window.__xss||0)+1">'


FORTILINK_DEMO = """config system global
    set hostname "FW-LINK"
end
config system interface
    edit "wan1"
        set vdom "root"
        set ip 203.0.113.10 255.255.255.248
        set role wan
        set type physical
    next
    edit "fortilink"
        set vdom "root"
        set ip 169.254.1.1 255.255.255.0
        set type aggregate
        set member "port5" "port6"
        set fortilink enable
    next
    edit "vlan_120"
        set vdom "root"
        set ip 10.120.20.1 255.255.255.0
        set interface "fortilink"
        set vlanid 120
        set type vlan
    next
    edit "linkgw"
        set vdom "root"
        set type tunnel
        set interface "wan1"
    next
end
config switch-controller security-policy 802-1X
    edit "ot-nac"
        set user-group "SSO_Guest_Users"
        set open-auth disable
    next
end
config switch-controller managed-switch
    edit "S124EPTF0000DEMO"
        set fsw-wan1-peer "fortilink"
        set name "FSW-DEMO-01"
        config ports
            edit "port1"
                set vlan "vlan_120"
                set port-security-policy "ot-nac"
                set description "PLC-120"
            next
            edit "port2"
                set vlan "vlan_120"
            next
            edit "port3"
                set vlan "vlan_120"
                set status down
            next
            edit "port24"
                set fortilink-port enable
                set type trunk
            next
        end
    next
end
config vpn ipsec phase1-interface
    edit "linkgw"
        set interface "wan1"
        set remote-gw 198.51.100.77
        set psksecret ENC demo
    next
end
config vpn ipsec phase2-interface
    edit "linkgw"
        set phase1name "linkgw"
        set src-subnet 10.120.20.0 255.255.255.0
        set dst-subnet 10.250.120.0 255.255.255.0
    next
end
config firewall policy
    edit 1
        set name "remote_to_plc"
        set srcintf "linkgw"
        set dstintf "vlan_120"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "HTTPS"
    next
end
"""


def seed(db_path: str) -> None:
    os.environ["IACS_DATABASE_URL"] = f"sqlite:///{db_path}"
    os.environ["IACS_REVIEW_ENABLED"] = "false"
    if Path(db_path).exists():
        Path(db_path).unlink()
    sys.path.insert(0, str(ROOT))
    from fastapi.testclient import TestClient
    from app.main import app
    from app.db import SessionLocal
    from app.models import FirewallDevice, FirewallInterface, Host, HostAddressHistory, NatRule

    def up(c, url, name, params=None, data=None):
        p = SAMPLES / name
        r = c.post(url, params=params or {}, data=data or {},
                   files={"file": (p.name, p.read_bytes(), "application/octet-stream")})
        print(f"  {url:36s} {name:34s} -> {r.status_code}")
        return r

    with TestClient(app) as c:
        # Sites (multi-site phase 1): every non-log upload names its site.
        site_a = c.post("/sites", json={"name": "Plant A", "code": "plant-a",
                                        "description": "Demo plant with the FortiGate"}).json()
        site_b = c.post("/sites", json={"name": "Plant B", "code": "plant-b",
                                        "description": "Demo plant with Cisco / pfSense"}).json()
        print(f"  sites: Plant A id={site_a.get('id')}, Plant B id={site_b.get('id')}")
        A, B = {"site": "plant-a"}, {"site": "plant-b"}
        # Firewalls
        up(c, "/ingest/fortigate-config", "sample_fortigate_config.txt", {**A, "firewall_name": "FW-OT"})
        up(c, "/ingest/firewall", "sample_firewall_cisco.txt",
           {**B, "firewall_device_name": "CISCO-EDGE", "purdue_zone_from": 4, "purdue_zone_to": 3})
        up(c, "/ingest/firewall", "sample_firewall_pfsense.xml", {**B, "firewall_device_name": "PFSENSE-LAB"})
        # Switches / L2
        for f in ("sample_switch_running_config.txt", "sample_switch_vlan_brief.txt",
                  "sample_switch_lldp_neighbors.txt", "sample_switch_cdp_neighbors.txt"):
            up(c, "/ingest/switch", f, {**A, "device_name": "SW-CORE"})
        up(c, "/ingest/mac-table", "sample_mac_table_cisco.txt", {**A, "device_name": "SW-CORE"})
        # 2026-10-19: a second FortiGate in Plant A with a FortiLink-managed FortiSwitch and a
        # site-to-site tunnel with phase 2 selectors (Firewall Ports "FortiSwitch:" line, the
        # Access Review tunnel_selector flag, the two switch port reviews)
        r = c.post("/ingest/fortigate-config", params={**A, "firewall_name": "FW-LINK"},
                   files={"file": ("fw-link.conf", FORTILINK_DEMO.encode())})
        print(f"  {'/ingest/fortigate-config':36s} {'fw-link.conf (inline)':34s} -> {r.status_code}")
        up(c, "/ingest/arp", "sample_arp_cisco.txt", A)
        up(c, "/ingest/arp", "sample_arp_unix.txt", B)
        # Traffic
        pcap = SAMPLES / "multi_protocol_sample.pcap"
        if not pcap.exists():
            subprocess.run([sys.executable, str(SAMPLES / "generate_sample_pcap.py")], cwd=ROOT, check=True)
        up(c, "/ingest/pcap", "multi_protocol_sample.pcap", A)
        # Phase 2 isolation demo: the SAME config / ARP table / capture in Plant B
        up(c, "/ingest/fortigate-config", "sample_fortigate_config.txt", {**B, "firewall_name": "FW-OT"})
        up(c, "/ingest/arp", "sample_arp_cisco.txt", B)
        up(c, "/ingest/pcap", "multi_protocol_sample.pcap", B)
        # Baselines
        up(c, "/ingest/baseline/comms-matrix", "sample_approved_comms.csv", {**A, "baseline_name": "B1"})
        up(c, "/ingest/baseline/approved-hosts", "sample_approved_hosts.csv", {**A, "baseline_name": "B1"})
        up(c, "/ingest/baseline/asset-inventory", "sample_asset_inventory.csv", {**A, "baseline_name": "B1"})
        # Logs, one with an XSS device name (devname= comes from the log line)
        up(c, "/ingest/forti-syslog", "sample_forti_events.cef", A)
        with tempfile.NamedTemporaryFile("w", suffix=".log", delete=False) as t:
            t.write(f'date=2026-09-30 time=10:00:00 devname="{XSS}" type=traffic subtype=forward '
                    'srcip=10.0.3.50 dstip=10.0.1.10 srcport=50000 dstport=23 proto=6 '
                    'action=accept policyid=99 service=TELNET app=teamviewer\n')
        r = c.post("/ingest/forti-syslog", params=A,
                   files={"file": ("xss.log", open(t.name, "rb"), "text/plain")})
        print(f"  xss syslog -> {r.status_code}")
        # F-10: a FortiGate traffic log naming FW-OT policy 10 -> last_matched on that rule
        r = c.post("/ingest/forti-syslog", params=A, files={"file": ("hit.log", (
            'date=2026-09-30 time=11:00:00 devname="FW-OT" type=traffic subtype=forward '
            'srcip=10.0.1.20 dstip=10.0.1.10 srcport=50100 dstport=502 proto=6 '
            'action=accept policyid=10 service=MODBUS\n').encode(), "text/plain")})
        print(f"  rule-hit syslog -> {r.status_code}")
        # F-11 multi-vendor syslog: the three vendor samples through /ingest/syslog
        for name, hint in (("sample_syslog_asa.log", "cisco_asa"), ("sample_syslog_pfsense.log", "auto"),
                           ("sample_syslog_panos.log", "panos")):
            up(c, "/ingest/syslog", name, {"vendor_hint": hint, **B})
        # ...and a bare ASA line (no hostname) whose device name comes from
        # the device_name fallback, planted with an XSS payload
        r = c.post("/ingest/syslog", params={"vendor_hint": "cisco_asa", "device_name": f"asa{XSS}", **B},
                   files={"file": ("asa_bare.log", (
                       "%ASA-4-106023: Deny tcp src outside:198.51.100.9/40000 dst inside:10.10.1.20/23 "
                       'by access-group "outside_access_in" [0x0, 0x0]\n').encode(), "text/plain")})
        print(f"  xss syslog (multi-vendor) -> {r.status_code} {r.json().get('stats', {}).get('events_created')}")
        # Phase 3 routing demo (no site): known asa-fw01 -> Plant B, unknown
        # rogue-fw9 -> held in the unmapped queue
        r = c.post("/ingest/syslog", files={"file": ("routing_demo.log", (
            "<166>Sep 30 2026 13:00:01 asa-fw01 : %ASA-6-106100: access-list outside_access_in "
            "permitted tcp outside/203.0.113.8(51299) -> inside/10.10.1.20(502) hit-cnt 1 first hit [0x1a2b3c4d, 0x0]\n"
            "<166>Sep 30 2026 13:00:02 rogue-fw9 : %ASA-6-106100: access-list outside_access_in "
            "permitted tcp outside/203.0.113.9(51300) -> inside/10.10.1.21(502) hit-cnt 1 first hit [0x1a2b3c4d, 0x0]\n"
            ).encode(), "text/plain")})
        routing = r.json().get("stats", {}).get("routing", {})
        print(f"  routing demo -> {r.status_code} routed={routing.get('routed')} unmapped={routing.get('unmapped')}")
        assert routing.get("unmapped") == 1 and "Plant B" in (routing.get("routed") or {}), routing
        # B-11 conflicts (held, never routed by guess):
        # (1) serial conflict - fgt-edge-a is registered at Plant A with one
        #     serial, a line arrives from "fgt-edge-a" with another serial
        r = c.post("/site-devices", json={"site": "plant-a", "device_name": "fgt-edge-a",
                                           "serial": "FGT60F0000000001", "vendor": "fortinet"})
        print(f"  register fgt-edge-a -> {r.status_code}")
        r = c.post("/ingest/forti-syslog", files={"file": ("replaced_unit.log", (
            'date=2026-09-30 time=14:00:00 devname="fgt-edge-a" devid="FGT60F0000009999" '
            'logid="0000000013" type=traffic subtype=forward srcip=10.0.1.20 dstip=10.0.1.10 '
            'srcport=50200 dstport=502 proto=6 action=accept policyid=7 service=MODBUS\n'
            ).encode(), "text/plain")})
        routing = r.json().get("stats", {}).get("routing", {})
        print(f"  serial conflict -> {r.status_code} conflicts={routing.get('conflicts')}")
        assert routing.get("serial_conflicts") == 1 and routing.get("conflicts") == 1, routing
        # (2) site mismatch - a file uploaded "for Plant A" carrying a line from
        #     asa-fw01, which is registered to Plant B
        r = c.post("/ingest/syslog", params={"site": "plant-a"}, files={"file": ("mismatch.log", (
            "<166>Sep 30 2026 14:05:01 asa-fw01 : %ASA-6-106100: access-list outside_access_in "
            "permitted tcp outside/203.0.113.10(51310) -> inside/10.10.1.20(502) hit-cnt 1 first hit [0x1a2b3c4d, 0x0]\n"
            ).encode(), "text/plain")})
        routing = r.json().get("stats", {}).get("routing", {})
        print(f"  site mismatch -> {r.status_code} site_conflicts={routing.get('site_conflicts')}")
        assert routing.get("site_conflicts") == 1 and routing.get("conflicts") == 1, routing
        # B-12 HA cluster: sample_fortigate_config.txt (uploaded to Plant A
        # above) has "config system ha / set mode a-p / set group-name
        # OT-FW-HA", so FG-OT-PERIMETER-01 is registered at Plant A as an a-p
        # cluster.  Its two units log with their own serials: the first
        # serial binds, the HA "member joined" log from that unit names the
        # peer (evidence), so the peer's traffic line routes to Plant A too.
        # (policyid 900 is in no uploaded config: the lines leave the F-10
        # rule hits / last_matched of FW-OT untouched.)
        r = c.post("/ingest/forti-syslog", files={"file": ("ha_cluster.log", (
            'date=2026-09-30 time=15:00:00 devname="FG-OT-PERIMETER-01" devid="FGT60FHA00000001" '
            'logid="0000000013" type=traffic subtype=forward srcip=10.0.1.20 dstip=10.0.1.10 '
            'srcport=50300 dstport=502 proto=6 action=accept policyid=900 service=MODBUS\n'
            'date=2026-09-30 time=15:00:05 devname="FG-OT-PERIMETER-01" devid="FGT60FHA00000001" '
            'logid="0108037894" type="event" subtype="ha" level="critical" vd="root" '
            'logdesc="Virtual cluster member joined" msg="Virtual cluster detected member join" '
            'vcluster=1 ha_group=0 sn="FGT60FHA00000002"\n'
            'date=2026-09-30 time=15:10:00 devname="FG-OT-PERIMETER-01" devid="FGT60FHA00000002" '
            'logid="0000000013" type=traffic subtype=forward srcip=10.0.1.21 dstip=10.0.1.10 '
            'srcport=50301 dstport=502 proto=6 action=accept policyid=900 service=MODBUS\n'
            ).encode(), "text/plain")})
        routing = r.json().get("stats", {}).get("routing", {})
        print(f"  HA cluster -> {r.status_code} members added={[m.get('serial') for m in routing.get('ha_members', [])]}")
        assert routing.get("conflicts") == 0 and len(routing.get("ha_members") or []) == 1, routing
        ha_dev = [d for d in c.get("/site-devices").json() if d["device_name"] == "fg-ot-perimeter-01"]
        assert len(ha_dev) == 1 and ha_dev[0]["is_ha"] and ha_dev[0]["ha_mode"] == "a-p" \
            and ha_dev[0]["site_id"] == site_a["id"] and len(ha_dev[0]["members"]) == 2, ha_dev

        # Purdue levels on the FortiGate legs; XSS in untrusted host fields
        db = SessionLocal()
        # rows added directly below belong to Plant A (app.sites flush filling)
        from app.sites import bind_ingest_site
        if site_a.get("id"):
            bind_ingest_site(db, site_a["id"])
        # port2 ("IT-OT DMZ", zone DMZ_ZONE) is the FortiGate's industrial
        # DMZ leg -> L3.5 (F-08), making FW-OT a 3-leg L1 / L3.5 / L4 firewall.
        for i in db.query(FirewallInterface):
            i.purdue_level = {"port1": 1, "port2": 3.5, "port3": 4}.get(i.name, i.purdue_level)
            # 2026-10-19: FW-LINK - the remote site behind the tunnel is L4, the FortiLink VLAN L2
            if i.name in ("linkgw", "vlan_120"):
                i.purdue_level = {"linkgw": 4, "vlan_120": 2}[i.name]
        # A remote-access jump host in the DMZ so the L3.5 band is populated.
        in_a = Host.site_id == site_a["id"]
        jh = db.query(Host).filter(in_a, Host.ip == "10.0.2.50").first()
        if jh is None:
            jh = Host(ip="10.0.2.50", sources=["demo"])
            db.add(jh)
        jh.hostname, jh.device_type = "jumphost-dmz", "jump_host"
        jh.purdue_level, jh.classification_source = 3.5, "manual"
        h = db.query(Host).filter(in_a).order_by(Host.id).first()
        if h:
            h.hostname = f"plc{XSS}"
            h.device_type = f"PLC{XSS}"
        # F-05: a VIP on FW-OT (DMZ address -> OT PLC) and a source NAT, the
        # VIP name carrying an XSS payload (names come from uploaded configs)
        # (mapped to a dedicated, manually classified L1 PLC so later
        # re-classification by the smoke tests cannot move it)
        plc = Host(ip="10.0.1.80", hostname="plc-nat", device_type="plc", purdue_level=1,
                   classification_source="manual", sources=["demo"])
        db.add(plc)
        dev = db.query(FirewallDevice).filter(FirewallDevice.site_id == site_a["id"],
                                              FirewallDevice.name == "FW-OT").first()
        if dev is not None:
            common = dict(firewall_id=dev.firewall_id, firewall_device_id=dev.id, device_name="FW-OT",
                          device_type="fortigate", source_file="demo-seed", enabled=True)
            db.add(NatRule(nat_type="dnat", name=f"VIP-PLC{XSS}", policy_id="20", protocol="any",
                           src_intf="port2", ext_ip="10.0.2.80/32", ext_port="any",
                           mapped_ip="10.0.1.80/32", mapped_port="any", **common))
            db.add(NatRule(nat_type="snat", name="OT-out", policy_id="30", protocol="any",
                           src_intf="port1", orig_src="10.0.1.0/24", mapped_ip="10.0.2.1/32", **common))
        # F-09: one host not seen for 90 days (flagged by /hosts/mark-stale
        # below); an address no sample file mentions, so re-ingests keep it stale
        now = datetime.now(timezone.utc)
        old = Host(ip="10.0.3.99", mac="00:1d:9c:00:03:99", hostname="retired-hmi", device_type="hmi",
                   purdue_level=2, classification_source="manual", sources=["demo"],
                   first_seen=now - timedelta(days=400), last_seen=now - timedelta(days=90))
        db.add(old)
        db.flush()
        # DHCP renumbering: the same MAC seen with two addresses
        for ip, src, first, last, n in (("10.0.3.98", "arp", 400, 200, 12), ("10.0.3.99", "pcap", 199, 90, 30)):
            db.add(HostAddressHistory(host_id=old.id, ip=ip, mac="00:1d:9c:00:03:99", source=src,
                                      first_seen=now - timedelta(days=first), last_seen=now - timedelta(days=last),
                                      observation_count=n))
        db.commit()
        db.close()
        r = c.post("/hosts/mark-stale", params={"older_than_days": 60, "site_id": site_a["id"]})
        print("  mark-stale", r.status_code, r.json())

        rv = c.post("/reviews/run")   # no site: every site is reviewed in turn
        print("  reviews", rv.status_code, {k: v.get("total_findings") for k, v in rv.json().get("sites", {}).items()})
        # Isolation proof: overlapping data -> independent rows per site
        from app.models import Firewall, Finding
        db = SessionLocal()
        try:
            for sid, label in ((site_a["id"], "Plant A"), (site_b["id"], "Plant B")):
                print(f"  {label}: hosts={db.query(Host).filter(Host.site_id == sid).count()} "
                      f"FW-OT={db.query(Firewall).filter(Firewall.site_id == sid, Firewall.name == 'FW-OT').count()} "
                      f"findings={db.query(Finding).filter(Finding.site_id == sid).count()}")
            fw_ot = db.query(Firewall).filter(Firewall.name == "FW-OT").all()
            assert len({f.site_id for f in fw_ot}) == 2, "FW-OT must exist once per site"
            ips_a = {h.ip for h in db.query(Host).filter(Host.site_id == site_a["id"], Host.ip.isnot(None))}
            ips_b = {h.ip for h in db.query(Host).filter(Host.site_id == site_b["id"], Host.ip.isnot(None))}
            assert ips_a & ips_b, "the seed must have overlapping IPs in Plant A and Plant B"
        finally:
            db.close()
        print("  attestation", c.post("/attestation", data={
            "checklist_id": "1.1", "attested_by": f"alice{XSS}", "attested_at": "2026-09-30",
            "notes": f"zone doc reviewed {XSS}", "baseline_name": "B1", "site": "plant-a"},
            files={"proof": (f"proof{XSS}.pdf", b"%PDF-1.4 demo", "application/pdf")}).status_code)
        print("  findings", c.get("/findings/summary").json())
        seed_access_review(c, site_a["id"], SessionLocal)


def seed_access_review(c, site_a_id, SessionLocal) -> None:
    """Access Review (docs/access-path-review.md, phase 3 UI) demo data.

    FW-OT's config already yields flagged access paths in Plant A
    (ot_upward_skip, cleartext_protocol / mgmt_protocol).  Added here, AFTER the review run so
    the findings counts above stay as they were:
      * a captured session jump host 10.0.2.50 (L3.5) -> 10.0.1.11 (L1)
        tcp/22, so the "JumpHost-to-OT-SSH" path is "Seen in capture";
      * a captured session 10.0.4.5 (L4) -> 10.0.1.11 (L1) tcp/502 that no
        policy allows, i.e. an "unexplained flow";
      * classifications via POST /access-paths/classify: one path Reviewed OK
        with a note (so it drops out of the report by default), the
        unexplained flow Permissive, and an XSS payload in a note /
        classified_by (both come from operators: rendered as text only).
    Plant B keeps the same paths unclassified (tags are per site)."""
    from app.models import Host, NetworkSession
    from app.sites import bind_ingest_site

    db = SessionLocal()
    try:
        bind_ingest_site(db, site_a_id)
        in_a = Host.site_id == site_a_id
        hosts = {ip: db.query(Host).filter(in_a, Host.ip == ip).order_by(Host.id).first()
                 for ip in ("10.0.2.50", "10.0.1.11", "10.0.4.5")}
        now = datetime.now(timezone.utc)
        for src, dst, sport, dport, proto in (("10.0.2.50", "10.0.1.11", 51022, 22, "ssh"),
                                              ("10.0.4.5", "10.0.1.11", 51502, 502, "modbus")):
            if hosts[src] is None or hosts[dst] is None:
                print(f"  access review: host {src} or {dst} missing - session not seeded")
                continue
            db.add(NetworkSession(src_host_id=hosts[src].id, dst_host_id=hosts[dst].id, src_port=sport,
                                  dst_port=dport, transport="tcp", protocol=proto,
                                  first_seen=now - timedelta(minutes=30), last_seen=now - timedelta(minutes=5),
                                  packet_count=12, byte_count=2400, source_file="demo-seed-access-review"))
        db.commit()
    finally:
        db.close()

    ap = c.get("/access-paths", params={"site_id": site_a_id}).json()
    paths, flows = ap.get("paths", []), ap.get("unmatched_observed") or []
    print(f"  access review: {len(paths)} paths ({sum(1 for p in paths if p['flags'])} flagged), "
          f"{len(flows)} unexplained flows, traffic {ap['counts']['by_traffic']}")
    assert any(p["flags"] for p in paths), "seed must have at least one flagged access path"
    items = []
    up = next((p for p in paths if p["direction"] == "up"), None)
    if up is not None:
        items.append({"tag_key": up["tag_key"], "classification": "reviewed_ok",
                      "note": "Historian upload via DMZ - approved conduit (CHG-1042)",
                      "classified_by": "demo-seed"})
    if flows:
        items.append({"tag_key": flows[0]["tag_key"], "classification": "permissive",
                      "note": f"Investigate: no rule allows this {XSS}", "classified_by": f"seed{XSS}"})
    r = c.post("/access-paths/classify", json={"site_id": site_a_id, "items": items})
    print(f"  access review classify -> {r.status_code} {[i['classification'] for i in r.json().get('items', [])]}")
    assert r.status_code == 200 and items, r.text
    ap = c.get("/access-paths", params={"site_id": site_a_id}).json()
    print(f"  access review counts: {ap['counts']}")


def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("--db", default=str(Path(tempfile.gettempdir()) / "iasc_ui_demo.db"))
    ap.add_argument("--port", type=int, default=8765)
    ap.add_argument("--no-serve", action="store_true")
    a = ap.parse_args()
    seed(a.db)
    if a.no_serve:
        return
    env = dict(os.environ, IACS_DATABASE_URL=f"sqlite:///{a.db}", IACS_REVIEW_ENABLED="false")
    os.execvpe(sys.executable, [sys.executable, "-m", "uvicorn", "app.main:app",
                                "--host", "127.0.0.1", "--port", str(a.port)], env | {"PYTHONPATH": str(ROOT)})


if __name__ == "__main__":
    main()
