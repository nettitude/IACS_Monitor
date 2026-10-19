"""
Firewall Ports (owner 2026-10-17): ports in config order with their untagged
subnet and VLAN sub-interfaces, aggregates naming their members, disabled /
WAN / HA flags, and the services the enabled permit rules allow between
interfaces (with cleartext / management / ALL warnings and captured-session
counts).  View only.
"""
import contextlib

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.main as main_mod
from app.db import Base, get_db
from app.models import Host, NetworkSession
from app.parsers.port_topology import _aggregate_members, _svc, _svc_kind

CFG = """config system global
    set hostname "FGT-PORTS"
end
config system interface
    edit "port1"
        set ip 10.10.1.1 255.255.255.0
        set alias "PLC-net"
        set role lan
    next
    edit "port2"
        set role lan
    next
    edit "port3"
        set ip 203.0.113.2 255.255.255.248
        set role wan
    next
    edit "port4"
        set status down
        set ip 10.99.9.1 255.255.255.0
    next
    edit "port5"
    next
    edit "port6"
    next
    edit "agg1"
        set type aggregate
        set member "port5" "port6"
        set ip 10.40.1.1 255.255.255.0
        set role lan
    next
    edit "port2.20"
        set vdom "root"
        set ip 10.10.2.1 255.255.255.0
        set interface "port2"
        set vlanid 20
        set type vlan
        set alias "HMI"
    next
    edit "port2.30"
        set vdom "root"
        set ip 10.10.3.1 255.255.255.0
        set interface "port2"
        set vlanid 30
        set type vlan
    next
end
config system zone
    edit "OT"
        set interface "port1" "port2.20" "port2.30"
    next
end
config firewall service custom
    edit "Modbus"
        set tcp-portrange 502
    next
end
config firewall policy
    edit 1
        set name "HMI-to-PLC"
        set srcintf "port2.20"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set service "Modbus"
        set action accept
    next
    edit 2
        set name "IT-to-OT"
        set srcintf "agg1"
        set dstintf "OT"
        set srcaddr "all"
        set dstaddr "all"
        set service "SSH" "HTTP"
        set action accept
    next
    edit 3
        set name "VLAN30-to-VLAN20"
        set srcintf "port2.30"
        set dstintf "port2.20"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
    next
    edit 4
        set name "deny"
        set srcintf "port1"
        set dstintf "agg1"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action deny
    next
    edit 5
        set name "disabled"
        set srcintf "port1"
        set dstintf "port3"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action accept
        set status disable
    next
end
"""


@contextlib.contextmanager
def api_ctx(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'pt.db'}", connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False)
    monkeypatch.setenv("IACS_REVIEW_ENABLED", "false")
    monkeypatch.setattr(main_mod, "init_db", lambda: None)

    def _get_db():
        s = Session()
        try:
            yield s
        finally:
            s.close()

    main_mod.app.dependency_overrides[get_db] = _get_db
    with TestClient(main_mod.app) as c:
        sid = c.post("/sites", json={"name": "PT", "code": "pt"}).json()["id"]
        r = c.post("/ingest/fortigate-config", params={"site": "pt", "firewall_name": "FGT-PORTS"},
                   files={"file": ("fw.conf", CFG.encode())})
        assert r.status_code == 200, r.text
        with Session() as s:
            hosts = {
                "plc": Host(site_id=sid, ip="10.10.1.10", mac="aa:00:00:00:01:10", device_type="plc", purdue_level=1),
                "plc2": Host(site_id=sid, ip="10.10.1.11", mac="aa:00:00:00:01:11", device_type="plc", purdue_level=1),
                "hmi": Host(site_id=sid, ip="10.10.2.10", mac="aa:00:00:00:02:10", device_type="hmi", purdue_level=2),
                "it": Host(site_id=sid, ip="10.40.1.50", mac="aa:00:00:00:04:50", device_type="workstation", purdue_level=4),
            }
            s.add_all(hosts.values()); s.flush()
            s.add_all([
                NetworkSession(src_host_id=hosts["hmi"].id, dst_host_id=hosts["plc"].id, dst_port=502, transport="tcp", protocol="modbus", packet_count=5),
                NetworkSession(src_host_id=hosts["hmi"].id, dst_host_id=hosts["plc2"].id, dst_port=502, transport="tcp", protocol="modbus", packet_count=5),
                NetworkSession(src_host_id=hosts["it"].id, dst_host_id=hosts["plc"].id, dst_port=22, transport="tcp", protocol="ssh", packet_count=5),
            ])
            s.commit()
        try:
            yield c, sid, Session
        finally:
            main_mod.app.dependency_overrides.pop(get_db, None)
            engine.dispose()


@pytest.fixture
def api(tmp_path, monkeypatch):
    with api_ctx(tmp_path, monkeypatch) as x:
        yield x


def test_helpers():
    assert _aggregate_members(CFG) == {"port5": "agg1", "port6": "agg1"}
    assert _svc("tcp", "502") == "tcp/502" and _svc("any", "any") == "ALL" and _svc("icmp", None) == "icmp"
    assert _svc_kind("tcp/23", {23}, {23}) == "cleartext-mgmt" and _svc_kind("tcp/80", {80}, set()) == "cleartext"
    assert _svc_kind("tcp/3389", set(), {3389}) == "mgmt" and _svc_kind("ALL", set(), set()) == "any"
    assert _svc_kind("tcp/502", set(), set()) == "ok" and _svc_kind("icmp", set(), set()) == "icmp"


def test_ports_subnets_and_links(api):
    c, sid, Session = api
    r = c.get("/topology/ports", params={"site_id": sid})
    assert r.status_code == 200, r.text
    j = r.json()
    assert len(j["firewalls"]) == 1
    fw = j["firewalls"][0]
    ports = {p["name"]: p for p in fw["ports"]}
    # config order; aggregate members are folded into the aggregate port; VLAN sub-interfaces ride on port2
    assert [p["name"] for p in fw["ports"]] == ["port1", "port2", "port3", "port4", "agg1"]
    assert ports["agg1"]["kind"] == "aggregate" and ports["agg1"]["members"] == ["port5", "port6"]
    assert ports["agg1"]["kind_label"].startswith("aggregate · port5 + port6")
    assert ports["port1"]["kind_label"] == "untagged · access" and ports["port1"]["subnets"][0]["cidr"] == "10.10.1.0/24"
    assert ports["port1"]["subnets"][0]["alias"] == "PLC-net" and ports["port1"]["subnets"][0]["zone"] == "OT"
    assert ports["port1"]["subnets"][0]["hosts"] == 2 and ports["port1"]["hosts"] == 2
    p2 = ports["port2"]
    assert p2["kind_label"] == "trunk · 2 VLANs" and [str(s["vlan"]) for s in p2["subnets"]] == ["20", "30"]
    assert all(s["tagged"] and s["parent"] == "port2" for s in p2["subnets"])
    assert p2["subnets"][0]["name"] == "port2.20" and p2["subnets"][0]["alias"] == "HMI" and p2["subnets"][0]["hosts"] == 1
    assert ports["port3"]["kind_label"] == "WAN · egress leg" and ports["port3"]["role"] == "wan"
    assert ports["port4"]["status"] == "down"
    # links: permits only, enabled only, zones expanded to their member interfaces
    links = {(l["src_name"], l["dst_name"]): l for l in j["links"]}
    assert ("port1", "agg1") not in links and ("port1", "port3") not in links           # deny / disabled
    hp = links[("port2.20", "port1")]
    assert hp["src_port"] == f"{fw['firewall_id']}:port2" and hp["dst_port"] == f"{fw['firewall_id']}:port1"
    assert [s["svc"] for s in hp["services"]] == ["tcp/502"] and hp["services"][0]["kind"] == "ok"
    assert hp["services"][0]["policies"] == ["1"] and hp["services"][0]["seen_sessions"] == 2
    assert hp["into_ot"] is False        # neither side labelled yet
    it = links[("agg1", "port1")]
    assert {s["svc"]: s["kind"] for s in it["services"]} == {"tcp/22": "mgmt", "tcp/80": "cleartext"}
    assert it["policies"] == ["2"] and it["warnings"] == 2
    assert next(s for s in it["services"] if s["svc"] == "tcp/22")["seen_sessions"] == 1
    assert ("agg1", "port2.20") in links and ("agg1", "port2.30") in links     # zone OT expanded
    intra = links[("port2.30", "port2.20")]
    assert intra["src_port"] == intra["dst_port"] and intra["services"][0]["svc"] == "ALL" and intra["services"][0]["kind"] == "any"
    assert j["hosts_counted"] == 4


def test_into_ot_follows_interface_labels(api):
    c, sid, Session = api
    from app.models import FirewallInterface
    with Session() as s:
        for i in s.query(FirewallInterface):
            if i.name == "port1":
                i.purdue_level = 1
            if i.name == "agg1":
                i.purdue_level = 4
        s.commit()
    j = c.get("/topology/ports", params={"site_id": sid}).json()
    links = {(l["src_name"], l["dst_name"]): l for l in j["links"]}
    assert links[("agg1", "port1")]["into_ot"] is True
    assert links[("port2.20", "port1")]["into_ot"] is True        # unlabelled source into L1
    p1 = next(p for p in j["firewalls"][0]["ports"] if p["name"] == "port1")
    assert p1["subnets"][0]["purdue_level"] == 1


def test_declaration_fills_unlabelled_subnet(api):
    c, sid, Session = api
    r = c.post("/subnets", params={"site_id": sid}, json={"cidr": "10.10.3.0/24", "purdue_level": 2, "zone_name": "HMI-30"})
    assert r.status_code in (200, 201), r.text
    j = c.get("/topology/ports", params={"site_id": sid}).json()
    p2 = next(p for p in j["firewalls"][0]["ports"] if p["name"] == "port2")
    v30 = next(s for s in p2["subnets"] if str(s["vlan"]) == "30")
    assert v30["declared"] == {"cidr": "10.10.3.0/24", "purdue_level": 2, "zone_name": "HMI-30"}


def test_empty_site_and_site_scoping(api):
    c, sid, Session = api
    sid2 = c.post("/sites", json={"name": "Other", "code": "ot2"}).json()["id"]
    j = c.get("/topology/ports", params={"site_id": sid2}).json()
    assert j["firewalls"] == [] and j["links"] == []
    assert c.get("/topology/ports", params={"site": "pt"}).json()["firewalls"][0]["name"] == "FGT-PORTS"


# ---- audit 2026-10-17 -------------------------------------------------------------------------

def test_multi_interface_any_and_multi_port_services(api):
    c, sid, Session = api
    from app.models import FirewallRule, Firewall
    with Session() as s:
        fw = s.query(Firewall).filter(Firewall.site_id == sid).one()
        s.add_all([
            FirewallRule(site_id=sid, firewall_id=fw.id, device_type="fortigate", device_name="FGT", policy_id=10, src_zone="port2.30,agg1", dst_zone="port1",
                         protocol="tcp", dst_port="23,80,443", action="permit", enabled=True, raw_line="multi"),
            FirewallRule(site_id=sid, firewall_id=fw.id, device_type="fortigate", device_name="FGT", policy_id=11, src_zone="any", dst_zone="port3",
                         protocol="tcp", dst_port="1024-65535", action="permit", enabled=True, raw_line="any"),
        ])
        s.commit()
    j = c.get("/topology/ports", params={"site_id": sid}).json()
    links = {(l["src_name"], l["dst_name"]): l for l in j["links"]}
    # "port2.30,agg1" -> both interfaces; Telnet / HTTP inside the port list are flagged
    for src in ("port2.30", "agg1"):
        l = links[(src, "port1")]
        svc = next(x for x in l["services"] if x["svc"] == "tcp/23,80,443")
        assert svc["kind"] == "cleartext-mgmt" and "10" in svc["policies"] and l["any_side"] is False
    # "any" fans out to every other interface of the firewall and is marked
    anys = [l for (a, b), l in links.items() if b == "port3" and "11" in l["policies"]]
    assert {l["src_name"] for l in anys} >= {"port1", "port2.20", "port2.30", "agg1", "port4"} and all(l["any_side"] for l in anys)
    assert anys[0]["services"][0]["kind"] == "wide"


def test_zone_definitions_drive_expansion_and_survive_name_clash(api, tmp_path):
    """Zones come from FirewallZoneDef keyed by firewall id (PAN-OS / ASA write only that table),
    so a second firewall whose device_name equals the first's name cannot steal them."""
    c, sid, Session = api
    from app.models import Firewall, FirewallInterface, FirewallRule, FirewallZoneDef
    with Session() as s:
        a = s.query(Firewall).filter(Firewall.site_id == sid).one()
        b = Firewall(site_id=sid, name="FGT-PORTS-B", device_name=a.name, vendor="paloalto")
        s.add(b); s.flush()
        s.add_all([FirewallInterface(firewall_id=b.id, name="ethernet1/1", ip_address="10.50.1.1", prefix_len=24,
                                     ip_cidr="10.50.1.1/24", network_cidr="10.50.1.0/24", iface_type="physical", status="up"),
                   FirewallInterface(firewall_id=b.id, name="ethernet1/2", ip_address="10.50.2.1", prefix_len=24,
                                     ip_cidr="10.50.2.1/24", network_cidr="10.50.2.0/24", iface_type="physical", status="up")])
        s.flush()
        s.add_all([FirewallZoneDef(firewall_id=b.id, vdom="vsys1", name="trust", members=["ethernet1/1"]),
                   FirewallZoneDef(firewall_id=b.id, vdom="vsys1", name="ot", members=["ethernet1/2"]),
                   FirewallRule(site_id=sid, firewall_id=b.id, device_type="paloalto", device_name="PAN", policy_id=None, policy_name="r1", src_zone="trust", dst_zone="vsys1/ot",
                                protocol="tcp", dst_port="80", action="permit", enabled=True, raw_line="pan")])
        s.commit()
    j = c.get("/topology/ports", params={"site_id": sid}).json()
    links = {(l["src_name"], l["dst_name"]): l for l in j["links"]}
    assert ("ethernet1/1", "ethernet1/2") in links and links[("ethernet1/1", "ethernet1/2")]["services"][0]["svc"] == "tcp/80"
    assert ("agg1", "port1") in links and ("agg1", "port2.20") in links           # firewall A keeps its OT zone
    a_ports = {p["name"]: p for p in next(f for f in j["firewalls"] if f["name"] == "FGT-PORTS")["ports"]}
    assert a_ports["port1"]["subnets"][0]["zone"] == "OT"
    b_ports = {p["name"]: p for p in next(f for f in j["firewalls"] if f["name"] == "FGT-PORTS-B")["ports"]}
    assert b_ports["ethernet1/1"]["subnets"][0]["zone"] == "trust"


def test_shared_network_counts_hosts_on_both_and_sub_interface_parent_from_alias(api):
    c, sid, Session = api
    from app.models import Firewall, FirewallInterface
    with Session() as s:
        b = Firewall(site_id=sid, name="ASA-B", device_name="ASA-B", vendor="cisco_asa")
        s.add(b); s.flush()
        s.add_all([FirewallInterface(firewall_id=b.id, name="inside", ip_address="10.10.1.2", prefix_len=24, ip_cidr="10.10.1.2/24",
                                     network_cidr="10.10.1.0/24", iface_type="physical", status="up"),
                   FirewallInterface(firewall_id=b.id, name="dmz", vlan_id="100", ip_address="10.60.1.1", prefix_len=24, ip_cidr="10.60.1.1/24",
                                     network_cidr="10.60.1.0/24", iface_type="vlan", status="up",
                                     alias="GigabitEthernet0/1.100 (security-level 50)")])
        s.commit()
    j = c.get("/topology/ports", params={"site_id": sid}).json()
    b_ports = {p["name"]: p for p in next(f for f in j["firewalls"] if f["name"] == "ASA-B")["ports"]}
    assert b_ports["inside"]["hosts"] == 2                                             # the two PLCs count here too
    a_ports = {p["name"]: p for p in next(f for f in j["firewalls"] if f["name"] == "FGT-PORTS")["ports"]}
    assert a_ports["port1"]["hosts"] == 2
    assert "GigabitEthernet0/1" in b_ports and b_ports["GigabitEthernet0/1"]["kind_label"] == "trunk · 1 VLAN"
    assert b_ports["GigabitEthernet0/1"]["subnets"][0]["name"] == "dmz" and j["hosts_counted"] == 4


def test_routing_switch_svis_and_site_scope(api):
    c, sid, Session = api
    from app.models import Firewall, FirewallInterface
    from app.parsers.l3_switch import VENDOR
    sid2 = c.post("/sites", json={"name": "Two", "code": "two"}).json()["id"]
    with Session() as s:
        sw = Firewall(site_id=sid2, name="SW-2", device_name="SW-2", vendor=VENDOR)
        s.add(sw); s.flush()
        s.add(FirewallInterface(firewall_id=sw.id, name="Vlan10", vlan_id="10", ip_address="10.70.10.1", prefix_len=24,
                                ip_cidr="10.70.10.1/24", network_cidr="10.70.10.0/24", iface_type="vlan", status="up"))
        s.commit()
    j = c.get("/topology/ports", params={"site_id": sid2}).json()
    assert [f["name"] for f in j["firewalls"]] == ["SW-2"] and j["firewalls"][0]["switch"] is True
    p = j["firewalls"][0]["ports"][0]
    assert p["kind"] == "svi" and p["kind_label"] == "SVI · VLAN 10" and p["subnets"][0]["tagged"] is False
    assert [f["name"] for f in c.get("/topology/ports", params={"site_id": sid}).json()["firewalls"]] == ["FGT-PORTS"]
