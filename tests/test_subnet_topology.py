"""
Network Topology (owner 2026-10-16): lanes by subnet / VLAN, hosts by function,
separators between lanes (firewall policies, routing switch, flat segment, Internet).
"""
import contextlib

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.main as main_mod
from app.db import Base, get_db
from app.models import Host, NetworkSession
from app.parsers.subnet_topology import function_of
from tests.test_sl0_conduit_rules import CFG, EXTRA4


@contextlib.contextmanager
def api_ctx(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'nt.db'}", connect_args={"check_same_thread": False})
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
        sid = c.post("/sites", json={"name": "NT", "code": "nt"}).json()["id"]
        # port1 10.10.1.0/24 (PLC), port2 10.10.2.0/24 (HMI), port3 10.40.1.0/24 (IT); policies 1-4
        r = c.post("/ingest/fortigate-config", params={"site": "nt", "firewall_name": "FW-NT"},
                   files={"file": ("fw.conf", CFG.replace("{EXTRA}", EXTRA4).encode())})
        assert r.status_code == 200, r.text
        with Session() as s:
            hosts = {
                "plc": Host(site_id=sid, ip="10.10.1.10", mac="aa:00:00:00:01:10", device_type="plc", purdue_level=1, classification_source="manual"),
                "plc2": Host(site_id=sid, ip="10.10.1.11", mac="aa:00:00:00:01:11", device_type="plc", purdue_level=1),
                "laptop": Host(site_id=sid, ip="10.10.1.50", mac="aa:00:00:00:01:50", vendor="Dell Inc."),        # unknown function on the PLC net
                "hmi": Host(site_id=sid, ip="10.10.2.10", mac="aa:00:00:00:02:10", device_type="hmi", purdue_level=2),
                "it": Host(site_id=sid, ip="10.40.1.50", mac="aa:00:00:00:04:50", device_type="workstation", purdue_level=4),
                "orphan": Host(site_id=sid, ip="192.168.77.9", mac="aa:00:00:00:77:09", device_type="historian"),   # no firewall net: inferred /24
                "ext": Host(site_id=sid, ip="93.184.216.34", mac=None),
            }
            s.add_all(hosts.values()); s.flush()
            s.add_all([
                NetworkSession(src_host_id=hosts["hmi"].id, dst_host_id=hosts["plc"].id, dst_port=502, transport="tcp", protocol="modbus", packet_count=5),
                NetworkSession(src_host_id=hosts["it"].id, dst_host_id=hosts["hmi"].id, dst_port=443, transport="tcp", protocol="unknown", packet_count=5),
                NetworkSession(src_host_id=hosts["orphan"].id, dst_host_id=hosts["plc2"].id, dst_port=102, transport="tcp", protocol="s7comm", packet_count=5),
                NetworkSession(src_host_id=hosts["it"].id, dst_host_id=hosts["ext"].id, dst_port=443, transport="tcp", protocol="unknown", packet_count=5),
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


def test_function_groups():
    assert function_of("plc") == "controller" and function_of("hmi") == "hmi" and function_of("engineering_workstation") == "engineering"
    assert function_of("historian") == "server" and function_of("switch") == "infrastructure" and function_of(None) == "unknown"
    assert function_of("workstation") == "it" and function_of("weird_server_x") == "server"


def test_lanes_functions_and_separators(api):
    c, sid, Session = api
    j = c.get("/topology/subnets", params={"site_id": sid}).json()
    lanes = {l["cidr"] or l["label"]: l for l in j["lanes"]}
    # 7 seeded hosts: the public one is an egress destination, and the 3 MAC-less address-object twins
    # the config upload created (same IPs) are folded into the captured hosts (audit 2026-10-17)
    assert j["hosts_total"] == 6
    assert len([h for h in lanes["10.10.1.0/24"]["hosts"] if h["ip"] == "10.10.1.10"]) == 1
    assert set(lanes) >= {"10.10.1.0/24", "10.10.2.0/24", "10.40.1.0/24", "192.168.77.0/24"}
    assert "External / Internet" not in lanes                      # public addresses are egress destinations
    plc = lanes["10.10.1.0/24"]
    assert plc["kind"] == "fw_interface" and plc["interfaces"][0]["name"] == "port1" and plc["interfaces"][0]["firewall"] == "FW-NT"
    assert plc["functions"]["controller"] == 2 and plc["functions"]["unknown"] == 1 and plc["mixed"] is True
    assert [h["function"] for h in plc["hosts"]][:2] == ["controller", "controller"]            # controllers first
    assert lanes["10.10.2.0/24"]["mixed"] is False and lanes["10.40.1.0/24"]["functions"]["it"] == 1
    inf = lanes["192.168.77.0/24"]
    assert inf["kind"] == "inferred" and inf["hosts"][0]["function"] == "server"
    # lane order: firewall networks, then inferred
    kinds = [l["kind"] for l in j["lanes"]]
    assert kinds.index("inferred") > kinds.index("fw_interface")
    seps = {(s["a"], s["b"]): s for s in j["separators"]}
    fw = seps[("net:10.10.1.0/24", "net:10.10.2.0/24")]
    assert fw["kind"] == "firewall" and fw["through"][0]["name"] == "FW-NT"
    assert set(fw["policies"]) == {"1", "4"} and fw["permit_policies"] == 2 and fw["sessions"] == 1 and fw["protocols"] == ["modbus"]
    it_hmi = seps[("net:10.10.2.0/24", "net:10.40.1.0/24")]
    assert it_hmi["kind"] == "firewall" and it_hmi["policies"] == ["2"]
    assert seps[("inferred:192.168.77.0/24", "net:10.10.1.0/24")]["kind"] == "unknown"
    assert not any("external" in k for k in seps)


def test_declaration_shows_on_the_lane_and_other_site_is_empty(api):
    c, sid, Session = api
    assert c.post("/subnets", params={"site_id": sid}, json={"cidr": "10.10.1.0/24", "purdue_level": 1, "zone_name": "Cell 1"}).status_code in (200, 201)
    j = c.get("/topology/subnets", params={"site_id": sid}).json()
    plc = next(l for l in j["lanes"] if l["cidr"] == "10.10.1.0/24")
    assert plc["declared"] == {"cidr": "10.10.1.0/24", "purdue_level": 1, "zone_name": "Cell 1"}
    other = c.post("/sites", json={"name": "Empty", "code": "empty"}).json()["id"]
    j2 = c.get("/topology/subnets", params={"site_id": other}).json()
    assert j2["lanes"] == [] and j2["hosts_total"] == 0


def test_per_host_flows_and_intra_lane_sessions(api):
    """Option 2 (owner 2026-10-16): each host carries its observed conversations with the peer's lane
    and what sits between; the lane carries its intra-lane session count (Lane Matrix diagonal)."""
    c, sid, Session = api
    with Session() as s:
        plc = s.query(Host).filter(Host.ip == "10.10.1.10", Host.mac.isnot(None)).one()
        plc2 = s.query(Host).filter(Host.ip == "10.10.1.11").one()
        s.add(NetworkSession(src_host_id=plc2.id, dst_host_id=plc.id, dst_port=502, transport="tcp", protocol="modbus", packet_count=9))
        s.commit()
    j = c.get("/topology/subnets", params={"site_id": sid}).json()
    lanes = {l["cidr"] or l["label"]: l for l in j["lanes"]}
    plc_lane = lanes["10.10.1.0/24"]
    assert plc_lane["intra_sessions"] == 1 and plc_lane["intra_protocols"] == ["modbus"]
    assert lanes["10.10.2.0/24"]["intra_sessions"] == 0
    plc = next(h for h in plc_lane["hosts"] if h["ip"] == "10.10.1.10" and h["mac"])
    assert plc["flow_count"] == 2
    by_peer = {f["peer_ip"]: f for f in plc["flows"]}
    hmi = by_peer["10.10.2.10"]
    assert hmi["direction"] == "from" and hmi["protocol"] == "modbus" and hmi["dst_port"] == 502
    assert hmi["same_lane"] is False and hmi["between"] == "firewall" and hmi["peer_lane"] == "net:10.10.2.0/24"
    same = by_peer["10.10.1.11"]
    assert same["same_lane"] is True and same["between"] == "same lane" and same["direction"] == "from"
    hmi_host = next(h for h in lanes["10.10.2.0/24"]["hosts"] if h["mac"])
    assert [f["direction"] for f in hmi_host["flows"]] == ["to", "from"] or len(hmi_host["flows"]) == 2
    assert j["flows_truncated"] == 0 and j["max_flows_per_host"] == 40


def test_egress_lane_destinations_sources_and_review(api):
    """Owner 2026-10-16: the egress lane - destinations outside the site (Internet, and the private
    corporate side as a sub-group), inside sources per lane with OT marked, review state, matrix data."""
    c, sid, Session = api
    with Session() as s:
        hmi = s.query(Host).filter(Host.ip == "10.10.2.10", Host.mac.isnot(None)).one()
        corp = Host(site_id=sid, ip="172.20.5.5", mac=None)                      # private, beyond the firewall
        s.add(corp); s.flush()
        s.add(NetworkSession(src_host_id=hmi.id, dst_host_id=corp.id, dst_port=445, transport="tcp", protocol="smb2_3", packet_count=4))
        s.commit()
    j = c.get("/topology/subnets", params={"site_id": sid}).json()
    eg = j["egress"]
    dests = {d["dest_key"]: d for d in eg["destinations"]}
    assert "93.184.216.34" in dests and "172.20.5.5" in dests
    inet, corp = dests["93.184.216.34"], dests["172.20.5.5"]
    assert inet["private"] is False and corp["private"] is True
    assert [d["private"] for d in eg["destinations"]] == sorted(d["private"] for d in eg["destinations"])   # Internet first
    assert inet["sources"][0]["ip"] == "10.40.1.50" and inet["sources"][0]["lane"] == "net:10.40.1.0/24" and inet["sources"][0]["ot"] is False
    assert corp["sources"][0]["ip"] == "10.10.2.10" and corp["sources"][0]["ot"] is True and corp["ot_sources"] == 1
    assert inet["status"] == "unreviewed" and inet["sessions"] == 1
    assert eg["summary"] == {"destinations": 2, "internet": 1, "private": 1, "approved": 0, "ot_sources": 1}
    assert eg["by_lane"]["net:10.40.1.0/24"]["ot"] is False and eg["by_lane"]["net:10.10.2.0/24"]["ot"] is True
    assert eg["by_lane"]["net:10.10.2.0/24"]["private"] == 1 and eg["by_lane"]["net:10.40.1.0/24"]["internet"] == 1
    assert "172.20.5.5" in eg["by_lane"]["net:10.10.2.0/24"]["destinations"]
    assert eg["wan_interfaces"] == []                                   # the test config has no default route
    # a review recorded here is the External comms record
    r = c.post("/external-comms/review", params={"site_id": sid}, json={"src": "10.40.1.50", "dest_key": "93.184.216.34", "status": "approved", "created_by": "pat"})
    assert r.status_code == 200, r.text
    j = c.get("/topology/subnets", params={"site_id": sid}).json()
    inet = next(d for d in j["egress"]["destinations"] if d["dest_key"] == "93.184.216.34")
    assert inet["status"] == "approved" and inet["sources"][0]["status"] == "approved" and j["egress"]["summary"]["approved"] == 1


def test_disabled_interfaces_are_not_lanes(api):
    """Owner 2026-10-17: an administratively-down interface (FortiOS set status down) makes no lane;
    its hosts fall back to the other evidence (here: an inferred lane)."""
    c, sid, Session = api
    from app.models import FirewallInterface
    with Session() as s:
        i = s.query(FirewallInterface).filter(FirewallInterface.name == "port3").one()
        i.status = "down"
        s.commit()
    j = c.get("/topology/subnets", params={"site_id": sid}).json()
    lanes = {l["cidr"] or l["label"]: l for l in j["lanes"]}
    assert lanes["10.40.1.0/24"]["kind"] == "inferred"          # not a firewall-interface lane any more
    assert all(i["name"] != "port3" for l in j["lanes"] for i in l["interfaces"])


# ---- audit 2026-10-17 -------------------------------------------------------------------------

def test_site_scope_multi_interface_policies_twins_and_wan(api):
    c, sid, Session = api
    from app.models import Firewall, FirewallInterface, FirewallRule, Host, PcapCapture
    from app.parsers.l3_switch import VENDOR
    sid2 = c.post("/sites", json={"name": "Two", "code": "two"}).json()["id"]
    with Session() as s:
        fw = s.query(Firewall).filter(Firewall.site_id == sid).one()
        s.add_all([
            # a policy naming two interfaces and one naming "any" permit into the PLC net
            FirewallRule(site_id=sid, firewall_id=fw.id, device_type="fortigate", device_name="FGT", policy_id=7, src_zone="port2,port3", dst_zone="port1",
                         protocol="tcp", dst_port="102", action="permit", enabled=True, raw_line="multi"),
            FirewallRule(site_id=sid, firewall_id=fw.id, device_type="fortigate", device_name="FGT", policy_id=8, src_zone="any", dst_zone="port1",
                         protocol="tcp", dst_port="443", action="permit", enabled=True, raw_line="any"),
            # the WAN leg has a public /29: not a lane
            FirewallInterface(firewall_id=fw.id, name="wan1", role="wan", ip_address="203.0.113.2", prefix_len=29,
                              ip_cidr="203.0.113.2/29", network_cidr="203.0.113.0/29", iface_type="physical", status="up"),
        ])
        # another site: a routing switch and a capture segment that must not leak into site 1
        sw = Firewall(site_id=sid2, name="SW-2", device_name="SW-2", vendor=VENDOR)
        s.add(sw); s.flush()
        s.add(FirewallInterface(firewall_id=sw.id, name="Vlan10", vlan_id="10", ip_address="10.70.10.1", prefix_len=24,
                                ip_cidr="10.70.10.1/24", network_cidr="10.70.10.0/24", iface_type="vlan", status="up"))
        s.add(Host(site_id=sid2, ip="10.70.10.5", mac="aa:00:00:00:70:05", device_type="plc"))
        s.commit()
    j = c.get("/topology/subnets", params={"site_id": sid}).json()
    keys = {l["key"] for l in j["lanes"]}
    assert "net:203.0.113.0/29" not in keys and "net:10.70.10.0/24" not in keys
    seps = {(x["a"], x["b"]): x for x in j["separators"]}
    hmi_plc = seps[("net:10.10.1.0/24", "net:10.10.2.0/24")]
    assert {"7", "8"} <= set(hmi_plc["policies"]) and hmi_plc["permit_policies"] == 4
    it_plc = seps[("net:10.10.1.0/24", "net:10.40.1.0/24")] if ("net:10.10.1.0/24", "net:10.40.1.0/24") in seps else None
    j2 = c.get("/topology/subnets", params={"site_id": sid2}).json()
    lane = next(l for l in j2["lanes"] if l["key"] == "net:10.70.10.0/24")
    assert lane["kind"] == "svi" and lane["interfaces"][0]["switch"] is True and len(lane["hosts"]) == 1
    assert j2["hosts_total"] == 1


def test_session_budget_counts_only_lane_sessions(api):
    c, sid, Session = api
    from app.parsers.subnet_topology import build
    with Session() as s:
        j = build(s, sid, session_limit=2)
        assert j["truncated"] is True and len(j["separators"]) >= 1          # two inter-lane sessions still seen
        j = build(s, sid, session_limit=1000)
        assert j["truncated"] is False


def test_policies_per_firewall_and_firewall_list(api):
    """Owner 2026-10-17: a site with several firewalls - each separator names every firewall between the
    two lanes with its own policies, and the payload lists the firewalls for the page selector."""
    c, sid, Session = api
    from app.models import Firewall, FirewallInterface, FirewallRule
    with Session() as s:
        b = Firewall(site_id=sid, name="FW-B", device_name="FW-B", vendor="fortigate")
        s.add(b); s.flush()
        s.add_all([FirewallInterface(firewall_id=b.id, name="lan1", ip_address="10.10.1.2", prefix_len=24, ip_cidr="10.10.1.2/24",
                                     network_cidr="10.10.1.0/24", iface_type="physical", status="up"),
                   FirewallInterface(firewall_id=b.id, name="lan2", ip_address="10.10.2.2", prefix_len=24, ip_cidr="10.10.2.2/24",
                                     network_cidr="10.10.2.0/24", iface_type="physical", status="up"),
                   FirewallRule(site_id=sid, firewall_id=b.id, device_type="fortigate", device_name="FW-B", policy_id=50,
                                src_zone="lan2", dst_zone="lan1", protocol="tcp", dst_port="502", action="permit", enabled=True, raw_line="b"),
                   FirewallRule(site_id=sid, firewall_id=b.id, device_type="fortigate", device_name="FW-B", policy_id=51,
                                src_zone="lan1", dst_zone="lan2", protocol="tcp", dst_port="80", action="deny", enabled=True, raw_line="b")])
        s.commit()
    j = c.get("/topology/subnets", params={"site_id": sid}).json()
    assert [(f["name"], f["lanes"]) for f in j["firewalls"]] == [("FW-NT", 3), ("FW-B", 2)]
    sep = next(x for x in j["separators"] if {x["a"], x["b"]} == {"net:10.10.1.0/24", "net:10.10.2.0/24"})
    assert sep["kind"] == "firewall" and [t["name"] for t in sep["through"]] == ["FW-NT", "FW-B"]
    a_, b_ = sep["through"]
    assert a_["policies"] == ["1", "4"] and a_["permit_policies"] == 2
    assert b_["policies"] == ["50", "51"] and b_["permit_policies"] == 1
    assert set(sep["policies"]) == {"1", "4", "50", "51"} and sep["permit_policies"] == 3
