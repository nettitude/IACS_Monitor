"""
F-01: parser branches that decide security findings, plus regressions for
the bugs the F-01 coverage work exposed:

  * common.name_has_keyword - whole-token zone/interface keyword matching
    (substring matching made "remote-dmz" an OT zone and "UNIT1_CONTROL"
    an IT zone);
  * common.get_or_create_host - a MAC-only observation of a MAC already on
    several hosts no longer creates a phantom MAC-only Host;
  * forti_config_parser - VPN destination classification (4.1), VDOM
    flattening, iprange expansion, FQDN-in-policy findings (severity by
    Purdue boundary / wildcard, re-open on re-ingest).
"""
import textwrap

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, configure_sqlite_engine
from app.models import CHECK_TYPE_REFERENCE, Finding, FirewallRule, FirewallZone, Host
from app.parsers import alert_engine as ae
from app.parsers.common import get_or_create_host, name_has_keyword
from app.parsers.forti_config_parser import flatten_global_vdom, ingest_fortigate_config
from app.parsers.mac_table_parser import ingest_mac_table


@pytest.fixture
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    configure_sqlite_engine(engine)
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()
    engine.dispose()


# ------------------------------------------------------- name_has_keyword --

OT = {"ot", "ics", "control", "plc", "rtu", "scada", "hmi", "field"}
IT = {"corp", "enterprise", "office", "business", "it", "user", "workstation", "desktop", "laptop"}


@pytest.mark.parametrize("name,keywords,expected", [
    ("OT_LAN", OT, True), ("ics-net", OT, True), ("Control Zone", OT, True),
    ("controllers", OT, True), ("PLC1", OT, True), ("plcs", OT, True), ("fieldbus", OT, True),
    ("remote-dmz", OT, False), ("Portugal-WAN", OT, False), ("physics-lab", OT, False),
    ("port2", OT, False), ("", OT, False), (None, OT, False),
    ("CORP_USERS", IT, True), ("IT-NET", IT, True), ("Offices", IT, True),
    ("UNIT1_CONTROL", IT, False), ("SECURITY_CELL", IT, False), ("digital-io", IT, False),
])
def test_name_has_keyword(name, keywords, expected):
    assert name_has_keyword(name, keywords) is expected


# ------------------------------------------------- MAC-only host identity --

def test_mac_only_observation_of_shared_mac_does_not_create_phantom(db):
    a = get_or_create_host(db, "10.0.1.1", "00:11:22:33:44:55", "arp")
    b = get_or_create_host(db, "10.0.1.10", "00:11:22:33:44:55", "inventory")
    assert a.id != b.id
    h = get_or_create_host(db, None, "0011.2233.4455", "mac_table")
    assert h.id in (a.id, b.id)
    assert db.query(Host).filter(Host.mac == "00:11:22:33:44:55").count() == 2
    # unknown MAC: still a new MAC-only row; single match: that row
    new = get_or_create_host(db, None, "00:aa:bb:cc:dd:ee", "mac_table")
    assert new.ip is None and new.id not in (a.id, b.id)
    single = get_or_create_host(db, "10.0.9.9", "00:99:99:99:99:99", "arp")
    assert get_or_create_host(db, None, "00:99:99:99:99:99", "mac_table").id == single.id


def test_mac_table_reingest_is_idempotent_for_shared_mac(db):
    get_or_create_host(db, "10.0.1.1", "00:11:22:33:44:55", "arp")
    get_or_create_host(db, "10.0.1.10", "00:11:22:33:44:55", "inventory")
    db.commit()
    table = "Vlan    Mac Address       Type        Ports\n" \
            "   1    0011.2233.4455    DYNAMIC     Gi1/0/1\n" \
            "  20    0011.2233.4466    DYNAMIC     Gi1/0/2\n"
    first = ingest_mac_table(table, db, device_name="SW1")
    n = db.query(Host).count()
    second = ingest_mac_table(table, db, device_name="SW1")
    assert db.query(Host).count() == n
    assert first["entries_found"] == second["entries_found"] == 2
    assert db.query(Host).filter(Host.ip.is_(None), Host.mac == "00:11:22:33:44:55").count() == 0


# ---------------------------------------------- misplaced device zoning --

def test_misplaced_devices_uses_whole_tokens(db):
    db.add_all([
        FirewallZone(device_name="FW", interface_name="p1", zone_name="UNIT1_CONTROL", ip_cidr="10.1.0.0/24"),
        FirewallZone(device_name="FW", interface_name="p2", zone_name="SECURITY_CELL", ip_cidr="10.2.0.0/24"),
        FirewallZone(device_name="FW", interface_name="p3", zone_name="CORP_USERS", ip_cidr="10.4.0.0/24"),
    ])
    for ip in ("10.1.0.5", "10.2.0.5", "10.4.0.5"):
        db.add(Host(ip=ip, purdue_level=1, device_type="plc"))
    db.flush()
    out = ae.review_misplaced_devices(db)
    assert [(f.detail["src_ip"], f.detail["zone_name"]) for f in out] == [("10.4.0.5", "CORP_USERS")]


# ------------------------------------------------- FortiGate: VPN to OT --

def _vpn_cfg(dstintfs):
    pols = "".join(textwrap.dedent(f"""\
        edit {i}
            set name "vpn-{i}"
            set srcintf "ssl.root"
            set dstintf "{d}"
            set srcaddr "all"
            set dstaddr "all"
            set action accept
            set service "RDP"
            set logtraffic all
        next
    """) for i, d in enumerate(dstintfs, start=1))
    return ("config vpn ssl settings\n    set source-interface \"wan1\"\n"
            "    set source-address \"VENDORS\"\nend\nconfig firewall policy\n" + pols + "end\n")


def test_vpn_destination_classification(db):
    dsts = ["OT_LAN", "remote-dmz", "IDMZ", "jumphost-net", "Plant-Net", "Portugal-office"]
    ingest_fortigate_config(_vpn_cfg(dsts), db, firewall_name="FW-VPN", generate_findings=True)
    got = {f.detail.get("dstintf"): (f.check_name, f.severity) for f in db.query(Finding)
           if f.check_name in ("config_vpn_direct_to_ot", "config_vpn_destination_unclear")}
    assert got == {
        "OT_LAN": ("config_vpn_direct_to_ot", "critical"),
        "Plant-Net": ("config_vpn_destination_unclear", "medium"),
        "Portugal-office": ("config_vpn_destination_unclear", "medium"),
    }


def test_vpn_without_routing_policy(db):
    cfg = "config vpn ssl settings\n    set source-interface \"wan1\"\nend\n" \
          "config firewall policy\n    edit 1\n        set srcintf \"port1\"\n" \
          "        set dstintf \"port2\"\n        set srcaddr \"all\"\n        set dstaddr \"all\"\n" \
          "        set action accept\n        set service \"HTTPS\"\n    next\nend\n"
    ingest_fortigate_config(cfg, db, firewall_name="FW", generate_findings=True)
    names = {f.check_name for f in db.query(Finding)}
    assert "config_vpn_no_routing_policy" in names
    assert "config_vpn_direct_to_ot" not in names


# --------------------------------------- FortiGate: VDOM, iprange, FQDN --

VDOM_CFG = textwrap.dedent("""\
    config global
        config system global
            set hostname "FGT-VDOM"
        end
    end
    config vdom
        edit root
            config firewall address
                edit "PLC-RANGE"
                    set type iprange
                    set start-ip 10.0.1.8
                    set end-ip 10.0.1.15
                next
                edit "ODD-RANGE"
                    set type iprange
                    set start-ip 10.0.1.20
                    set end-ip 10.0.1.22
                next
                edit "BAD-RANGE"
                    set type iprange
                    set start-ip 10.0.1.30
                    set end-ip banana
                next
                edit "UPDATES"
                    set type fqdn
                    set fqdn "updates.vendor.example"
                next
            end
            config firewall policy
                edit 1
                    set srcintf "port1"
                    set dstintf "port2"
                    set srcaddr "PLC-RANGE"
                    set dstaddr "ODD-RANGE"
                    set action accept
                    set service "HTTPS"
                next
                edit 2
                    set srcintf "port1"
                    set dstintf "port2"
                    set srcaddr "BAD-RANGE"
                    set dstaddr "UPDATES"
                    set action accept
                    set service "HTTPS"
                next
            end
        next
        edit ot
            config firewall address
                edit "ANY-CLOUD"
                    set type wildcard-fqdn
                    set fqdn "*.cloud.example"
                next
            end
            config firewall policy
                edit 3
                    set srcintf "port3"
                    set dstintf "port4"
                    set srcaddr "all"
                    set dstaddr "ANY-CLOUD"
                    set action accept
                    set service "HTTPS"
                next
            end
        next
    end
""")


def test_flatten_global_vdom_merges_and_reports_collisions(caplog):
    assert flatten_global_vdom({"firewall policy": {"1": {}}}) == {"firewall policy": {"1": {}}}
    parsed = {
        "global": {"system global": {"hostname": "x"}},
        "vdom": {"root": {"firewall policy": {"1": {"name": "a"}}, "odd": "scalar"},
                 "ot": {"firewall policy": {"1": {"name": "b"}, "2": {"name": "c"}}}},
        "extra": {"k": 1}, "scalar_top": "v",
    }
    with caplog.at_level("WARNING"):
        flat = flatten_global_vdom(parsed)
    assert flat["firewall policy"] == {"1": {"name": "b"}, "2": {"name": "c"}}
    assert flat["odd"] == "scalar" and flat["extra"] == {"k": 1} and flat["scalar_top"] == "v"
    assert "collision" in caplog.text


def _fqdn(db):
    return {f.detail["policy_id"]: f for f in db.query(Finding).filter(Finding.check_name == "fqdn_in_policy")}


def test_vdom_iprange_and_fqdn_findings(db):
    st = ingest_fortigate_config(VDOM_CFG, db, firewall_name="FGT-VDOM", generate_findings=True)
    rules = {r.policy_id: r for r in db.query(FirewallRule)}
    assert rules["1"].src == "10.0.1.8/29"                     # CIDR-aligned range -> one network
    dsts = {r.dst for r in db.query(FirewallRule).filter(FirewallRule.policy_id == "1")}
    assert dsts == {"10.0.1.20/31", "10.0.1.22/32"}            # minimal covering CIDRs
    assert st["fqdn_objects_in_policy"] == 2
    f = _fqdn(db)
    default_sev = CHECK_TYPE_REFERENCE["fqdn_in_policy"][2]
    assert f["2"].severity == default_sev and f["2"].detail["fqdn_value"] == "updates.vendor.example"
    assert f["3"].severity == "high" and f["3"].title.startswith("Wildcard-FQDN")

    # re-ingest at an OT boundary: same findings, re-opened and raised to critical
    for x in f.values():
        x.status = "closed"
    db.commit()
    ingest_fortigate_config(VDOM_CFG, db, firewall_name="FGT-VDOM", generate_findings=True,
                            purdue_zone_from=3, purdue_zone_to=1)
    f2 = _fqdn(db)
    assert {k: (v.id, v.status, v.severity) for k, v in f2.items()} == \
        {k: (f[k].id, "open", "critical") for k in f}
    assert all("[Purdue L1 boundary]" in v.title for v in f2.values())
    assert all(v.detail["purdue_zone_to"] == 1 for v in f2.values())


def test_fqdn_finding_new_at_ot_boundary(db):
    ingest_fortigate_config(VDOM_CFG, db, firewall_name="FGT-B", generate_findings=True,
                            purdue_zone_from=2, purdue_zone_to=0)
    f = _fqdn(db)
    assert {v.severity for v in f.values()} == {"critical"}
    assert "field devices" in f["2"].detail["description"]
