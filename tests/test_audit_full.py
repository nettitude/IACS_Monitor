"""Audit 2026-10-06 (full project review): regression tests for the confirmed
findings - see docs/code-review-remediation.md, section
"Audit 2026-10-06 (full project review)"."""
import textwrap

import pytest

from app.models import (ApprovedHost, Baseline, Finding, Firewall, FirewallDevice, FirewallInterface,
                        FirewallRule, Host, NetworkSession, PcapCapture, Site)
from app.parsers import l3_switch as l3
from app.parsers import rule_match as rm
from app.parsers.arp_parser import parse_arp_table
from app.parsers.baseline_parser import ingest_approved_hosts, ingest_reviewed_policies
from app.parsers.firewall_parser import ingest_firewall_config, parse_cisco_acl
from app.parsers.forti_config_parser import _config_findings, _hardening_findings, ingest_fortigate_config
from app.parsers.host_identity import HostIdentityResolver
from app.parsers.nat_paths import NatIndex
from app.parsers.switch_hardening import check_switch_config
from app.parsers.switch_parser import _expand_hp_port_list
from app.sites import ingest_site
from tests.test_access_paths import _site, db  # noqa: F401

FG = """config system global
    set hostname FG-A
end
config system interface
    edit "port1"
        set ip 10.10.0.1 255.255.0.0
    next
    edit "port2"
        set ip 10.50.0.1 255.255.255.0
    next
end
config firewall address
    edit "slash"
        set subnet 10.60.0.0/16
    next
    edit "h1"
        set subnet 10.10.1.5 255.255.255.255
    next
end
config firewall addrgrp
    edit "grp"
        set member "slash" "h1"
    next
end
config firewall policy
    edit 1
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
        set comments "ops"
    next
    edit 2
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "h1" "all"
        set dstaddr "grp"
        set service "ALL"
        set action accept
    next
end
"""


def _rules(db, fw):
    return db.query(FirewallRule).filter(FirewallRule.firewall_id == fw.id).all()


# ---------------------------------------------------------------- C-group --

def test_c9_host_netmask_is_not_the_cisco_any_wildcard():
    assert str(rm.parse_address_spec("10.1.1.5 255.255.255.255")) == "10.1.1.5/32"
    assert str(rm.parse_address_spec("0.0.0.0 255.255.255.255")) == "0.0.0.0/0"
    assert str(rm.parse_address_spec("10.1.1.0 0.0.0.255")) == "10.1.1.0/24"


def test_c7_eval_cache_is_bounded():
    from app.parsers import reachability as r

    class Ctx:
        _eval_cache = {}
    ctx = Ctx()
    for i in range(r._EVAL_CACHE_MAX + 10):
        r._cache_put(ctx, ("k", i), i)
    assert len(ctx._eval_cache) <= r._EVAL_CACHE_MAX
    assert ("k", r._EVAL_CACHE_MAX + 9) in ctx._eval_cache          # newest kept


def test_c5_nat_index_is_keyed_per_vdom(db):
    """Two VDOMs reuse policy id 1; the SNAT entry of one must not apply to the other."""
    from app.models import NatRule
    sid = _site(db, "nat")
    fw = Firewall(site_id=sid, name="FG", vendor="fortigate")
    db.add(fw)
    db.flush()
    for vd, pool in (("it", "203.0.113.10"), ("ot", "198.51.100.10")):
        db.add(NatRule(site_id=sid, firewall_id=fw.id, vdom=vd, policy_id="1", nat_type="snat",
                       device_type="fortigate", enabled=True, orig_src="any", mapped_ip=pool))
    db.flush()
    idx = NatIndex.build(db)
    keys = set(idx.snat)
    assert (fw.id, "it", "1") in keys and (fw.id, "ot", "1") in keys
    assert not any(len(k) != 3 for k in keys)


# ---------------------------------------------------------------- D-group --

def test_d1_reingest_keeps_owner_conduit_and_last_matched(db):
    from datetime import datetime, timezone
    sid = _site(db, "d1")
    with ingest_site(db, sid):
        ingest_fortigate_config(FG, db, firewall_name="FG-A")
        db.flush()
        ingest_reviewed_policies("policy_id,conduit,owner\n2,IT-OT,alice\n", db, baseline_name="b")
        fw = db.query(Firewall).filter(Firewall.site_id == sid).one()
        r2 = [r for r in _rules(db, fw) if r.policy_id == "2"]
        assert r2 and all(r.conduit == "IT-OT" and r.owner == "alice" for r in r2)
        when = datetime(2026, 10, 1, tzinfo=timezone.utc)
        for r in r2:
            r.last_matched = when
        db.flush()
        st = ingest_fortigate_config(FG, db, firewall_name="FG-A")
        assert st["rules_carried"] == 2           # policy 1 (comment owner) and policy 2
    r2 = [r for r in _rules(db, fw) if r.policy_id == "2"]
    assert r2 and all(r.conduit == "IT-OT" and r.owner == "alice" for r in r2)
    assert all(r.last_matched.replace(tzinfo=timezone.utc) == when for r in r2)
    r1 = [r for r in _rules(db, fw) if r.policy_id == "1"]
    assert all(r.owner == "ops" for r in r1)            # the config's own comment still wins


def test_d2_empty_object_group_keeps_the_rule_visible():
    cfg = """hostname ASA
object-group network EMPTY
access-list OUT extended permit tcp object-group EMPTY host 10.1.1.1 eq 22
access-list OUT extended permit tcp any host 10.1.1.2 eq 22
"""
    stats = {}
    rows = parse_cisco_acl(cfg, stats)
    assert any(r["src"] == "unresolved:EMPTY" for r in rows), rows
    assert stats.get("empty_object_groups") == 1


def test_d3_any_any_detected_on_a_later_expanded_row():
    pols = [
        {"policy_id": "7", "action": "permit", "src": "10.1.1.5/32", "dst": "any", "protocol": "any",
         "dst_port": "any", "src_zone": "a", "dst_zone": "b"},
        {"policy_id": "7", "action": "permit", "src": "any", "dst": "any", "protocol": "any",
         "dst_port": "any", "src_zone": "a", "dst_zone": "b"},
        {"policy_id": "7", "action": "permit", "src": "10.1.1.5/32", "dst": "10.0.0.0/8", "protocol": "any",
         "dst_port": "any", "src_zone": "a", "dst_zone": "b"},
    ]
    f = _config_findings(pols, {}, {}, {}, "FG")
    assert [x for x in f if x["check_name"] == "config_permit_any_any_any"]
    f = _hardening_findings({}, pols, {}, {}, {}, [], "FG")
    broad = [x for x in f if x["check_name"] == "config_overly_broad_subnet"]
    assert len(broad) == 1 and broad[0]["detail"]["ref_key"] == "7:dst:10.0.0.0/8"      # D6


def test_d4_vpn_policy_with_srcintf_list():
    from app.parsers.forti_config_parser import _extract_vpn_settings
    parsed = {
        "vpn ssl settings": {"source-interface": ["port1"]},
        "firewall policy": {"5": {"srcintf": ["ssl.root", "port3"], "dstintf": ["port2"],
                                  "dstaddr": ["all"], "action": "accept"}},
    }
    out = _extract_vpn_settings(parsed)
    assert [p["policy_id"] for p in out["vpn_firewall_policies"]] == ["5"]


def test_d5_long_strings_are_clipped_to_the_column_length(db):
    sid = _site(db, "d5")
    r = FirewallRule(site_id=sid, device_name="d", device_type="fortigate", action="permit",
                     src="too-large:" + "x" * 300, dst="any", dst_port="p" * 400, policy_name="n" * 500)
    db.add(r)
    db.flush()
    assert len(r.src) == 128 and len(r.dst_port) == 255 and len(r.policy_name) <= 255


def test_d7_approved_hosts_normalise_identity(db):
    sid = _site(db, "d7")
    with ingest_site(db, sid):
        st = ingest_approved_hosts(
            "ip,mac,hostname,role\n10.1.1.5,AA-BB-CC-DD-EE-01,jh,jump_host\n"
            "224.0.0.1,aa:bb:cc:dd:ee:02,bad,hmi\n", db, baseline_name="b")
    rows = db.query(ApprovedHost).all()
    assert [(h.ip, h.mac) for h in rows] == [("10.1.1.5", "aa:bb:cc:dd:ee:01")]
    assert st["skipped_bad_identity"] == 1


def test_d8_cidr_subnet_form(db):
    sid = _site(db, "d8")
    with ingest_site(db, sid):
        ingest_fortigate_config(FG, db, firewall_name="FG-A")
    fw = db.query(Firewall).filter(Firewall.site_id == sid).one()
    dsts = {r.dst for r in _rules(db, fw) if r.policy_id == "2"}
    assert "10.60.0.0/16" in dsts and "10.10.1.5/32" in dsts


def test_d9_config_hostname_beats_the_file_name(db):
    sid = _site(db, "d9")
    with ingest_site(db, sid):
        st = ingest_fortigate_config(FG, db, fallback_name="fw-backup-1")
        assert st["device_name"] == "FG-A"
        st = ingest_fortigate_config(FG.replace("    set hostname FG-A\n", ""), db, fallback_name="fw-backup-1")
        assert st["device_name"] == "fw-backup-1"


def test_d11_xml_entities_are_not_expanded(db):
    bomb = """<?xml version="1.0"?>
<!DOCTYPE lolz [<!ENTITY lol "lol"><!ENTITY lol2 "&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;&lol;">]>
<pfsense><filter><rule><type>pass</type><descr>&lol2;</descr></rule></filter></pfsense>"""
    sid = _site(db, "d11")
    with ingest_site(db, sid):
        try:
            st = ingest_firewall_config(bomb, db, vendor_hint="pfsense", firewall_device_name="pf")
        except Exception as exc:                                     # noqa: BLE001
            st = {"error": str(exc)}
    assert db.query(FirewallRule).filter(FirewallRule.site_id == sid, FirewallRule.raw_line.like("%lollol%")).count() == 0
    assert "lollollol" not in str(st)


# ---------------------------------------------------------------- E-group --

SW_HP = """hostname "SW-HP"
snmp-server community "public" unrestricted
"""


def test_e_h1_switch_hardening_stays_in_its_site(db):
    a, b = _site(db, "ea"), _site(db, "eb")
    with ingest_site(db, a):
        check_switch_config(db, SW_HP, "SW-HP", "hp")
    with ingest_site(db, b):
        check_switch_config(db, SW_HP, "SW-HP", "hp")
    assert db.query(Finding).filter(Finding.site_id == a, Finding.status == "open").count() == 1
    assert db.query(Finding).filter(Finding.site_id == b, Finding.status == "open").count() == 1
    with ingest_site(db, b):                     # community removed in site b only
        check_switch_config(db, 'hostname "SW-HP"\n', "SW-HP", "hp")
    assert db.query(Finding).filter(Finding.site_id == a, Finding.status == "open").count() == 1
    assert db.query(Finding).filter(Finding.site_id == b, Finding.status == "open").count() == 0


def test_e_m2_arp_table_drops_group_rows():
    rows = parse_arp_table("""Internet  224.0.0.251   0  0100.5e00.00fb  ARPA  Vlan10
Internet  10.1.1.255    0  ffff.ffff.ffff  ARPA  Vlan10
Internet  10.1.1.5      0  0011.2233.4455  ARPA  Vlan10
""")
    assert [(r.ip, r.mac) for r in rows] == [("10.1.1.5", "0011.2233.4455")]


def test_e_m4_dual_stack_host_is_not_router_like(db):
    sid = _site(db, "em4")
    with ingest_site(db, sid):
        db.add(Host(site_id=sid, ip="10.1.1.5", mac=None))
        db.add(Host(site_id=sid, ip=None, mac="aa:bb:cc:00:00:05"))
        db.flush()
        res = HostIdentityResolver(db, "pcap", observed={
            "aa:bb:cc:00:00:05": {"10.1.1.5", "fe80::1", "2001:db8::5"}})
        res.resolve("10.1.1.5", "aa:bb:cc:00:00:05")
        res.finish()
    assert db.query(Host).filter(Host.site_id == sid).count() == 1          # folded: one device


def test_e_m5_hp_port_range_is_bounded():
    assert _expand_hp_port_list("1-4,A1-A2") == ["1", "2", "3", "4", "A1", "A2"]
    out = _expand_hp_port_list("1-999999999")
    assert out == ["1-999999999"]


def test_e_m3_profinet_multicast_goes_to_the_group_marker(db, tmp_path):
    import struct
    from app.models import GROUP_MARKER_MAC
    from app.parsers.pcap_parser import ingest_pcap
    frames = []
    # DCP identify-all: dst 01:0e:cf:00:00:00, ethertype 0x8892, frame id 0xfefe
    dst = bytes.fromhex("010ecf000000")
    src = bytes.fromhex("001122334455")
    pn = struct.pack("!H", 0xFEFE) + b"\x05\x00" + b"\x00" * 10
    frames.append(dst + src + b"\x88\x92" + pn + b"\x00" * 30)
    hdr = struct.pack("<IHHiIII", 0xA1B2C3D4, 2, 4, 0, 0, 65535, 1)
    body = b"".join(struct.pack("<IIII", 1, 0, len(f), len(f)) + f for f in frames)
    p = tmp_path / "pn.pcap"
    p.write_bytes(hdr + body)
    sid = _site(db, "em3")
    with ingest_site(db, sid):
        st = ingest_pcap(str(p), db)
    assert st.get("profinet_group_packets") == 1
    macs = {h.mac for h in db.query(Host).filter(Host.site_id == sid)}
    assert "01:0e:cf:00:00:00" not in macs and GROUP_MARKER_MAC in macs


# ---------------------------------------------------------------- F-group --

def test_f9_switch_removal_clears_capture_and_device_references(db):
    sid = _site(db, "f9")
    sw = """hostname SW
ip routing
interface Vlan10
 ip address 10.10.0.254 255.255.255.0
interface Vlan20
 ip address 10.20.0.254 255.255.255.0
"""
    with ingest_site(db, sid):
        st = l3.sync_switch(db, "SW", sw)
        assert st["enforcement_point"]
        fw = db.query(Firewall).filter(Firewall.site_id == sid, Firewall.name == "SW").one()
        iface = db.query(FirewallInterface).filter(FirewallInterface.firewall_id == fw.id).first()
        cap = PcapCapture(site_id=sid, filename="x.pcap", firewall_id=fw.id, interface_id=iface.id,
                          suggested_interface_id=iface.id)
        dev = FirewallDevice(site_id=sid, name="SW", vendor="cisco_ios", firewall_id=fw.id)
        db.add_all([cap, dev])
        db.flush()
        st = l3.sync_switch(db, "SW", "hostname SW\nno ip routing\n")      # no longer routing -> removed
    db.flush()
    assert db.query(Firewall).filter(Firewall.site_id == sid).count() == 0
    assert (cap.firewall_id, cap.interface_id, cap.suggested_interface_id) == (None, None, None)
    assert dev.firewall_id is None


def test_f8_report_refuses_an_unscoped_multi_site_db(tmp_path, capsys):
    import generate_report as gr
    from sqlalchemy import create_engine
    from app.db import Base
    p = tmp_path / "r.db"
    e = create_engine(f"sqlite:///{p}")
    Base.metadata.create_all(e)
    with e.begin() as c:
        c.exec_driver_sql("INSERT INTO sites (name, code) VALUES ('a','a'), ('b','b')")
    rc = gr.main(["--db", f"sqlite:///{p}", "--out", str(tmp_path / "r.pdf")])
    assert rc == 2 and "2 sites" in capsys.readouterr().err
