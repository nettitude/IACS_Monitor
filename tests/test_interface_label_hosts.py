"""SF-8a: a host on the network of a labelled firewall interface with no
evidence of its own takes that interface's level (source
``interface_label``); stronger evidence wins; the label follows the
interface (relabel / clear) and never identifies the device."""
from datetime import datetime, timezone

from app.models import Firewall, FirewallInterface, Host, Site, SubnetZone
from tests.test_cov_routes import _api


def _seed(c):
    now = datetime.now(timezone.utc)
    with c.Session() as s:
        site = Site(name="Plant", code="p")
        s.add(site)
        s.flush()
        fw = Firewall(name="FW-SITE", device_name="FW-SITE", vendor="fortigate", site_id=site.id)
        s.add(fw)
        s.flush()
        p1 = FirewallInterface(firewall_id=fw.id, name="port1", ip_address="10.50.1.1", prefix_len=24,
                               ip_cidr="10.50.1.1/24", network_cidr="10.50.1.0/24", purdue_level=1)
        p2 = FirewallInterface(firewall_id=fw.id, name="port2", ip_address="10.50.2.1", prefix_len=24,
                               ip_cidr="10.50.2.1/24", network_cidr="10.50.2.0/24", purdue_level=3)
        p3 = FirewallInterface(firewall_id=fw.id, name="port3", ip_address="10.50.3.1", prefix_len=24,
                               ip_cidr="10.50.3.1/24", network_cidr="10.50.3.0/24")           # not labelled
        s.add_all([p1, p2, p3])
        s.flush()

        def host(ip, mac, **kw):
            s.add(Host(ip=ip, mac=mac, site_id=site.id, first_seen=now, last_seen=now, sources=["pcap"], **kw))
        host("10.50.1.200", "00:00:00:00:01:c8")                                              # rogue laptop
        host("10.50.1.11", "00:00:00:00:01:0b", device_type="plc", purdue_level=1, classification_source="protocol_inferred")
        host("10.50.1.21", "00:00:00:00:01:15", device_type="ics_protocol_client_unclassified",
             classification_source="protocol_client_hint")
        host("10.50.2.10", "00:00:00:00:02:0a")                                               # SCADA server, no evidence
        host("10.50.2.20", "00:00:00:00:02:14", device_type="engineering_workstation", purdue_level=3,
             classification_source="manual")
        host("10.50.2.30", "00:00:00:00:02:1e", device_type="hmi", purdue_level=2, classification_source="vlan_inferred")
        host("10.50.3.5", "00:00:00:00:03:05")                                                # behind the unlabelled port
        host("10.50.1.1", "00:00:00:00:01:01", device_type="router", classification_source="router")
        s.commit()
        return site.id, {"port1": p1.id, "port2": p2.id, "port3": p3.id}


def _hosts(c, sid):
    hs = c.get("/hosts", params={"site_id": sid, "limit": 5000}).json()
    hs = hs if isinstance(hs, list) else hs.get("hosts") or hs.get("items")
    return {h["ip"]: (h["purdue_level"], h["classification_source"], h["device_type"]) for h in hs}


def test_hosts_take_the_interface_label(tmp_path):
    with _api(tmp_path / "il.db") as c:
        sid, ifs = _seed(c)
        # nothing applied yet: labelling (any interface) runs the propagation
        r = c.post("/topology/set-interface-side", params={"site_id": sid},
                   json={"interface_id": ifs["port3"], "purdue_level": 4, "side": "inside"})
        assert r.status_code == 200, r.text
        h = _hosts(c, sid)
        assert h["10.50.1.200"] == (1, "interface_label", None)           # the laptop is L1 by its interface
        assert h["10.50.2.10"] == (3, "interface_label", None)
        assert h["10.50.3.5"] == (4, "interface_label", None)
        # owner 2026-10-14: automatic levels follow the interface too (device type kept);
        # only a manual classification stays
        assert h["10.50.1.11"] == (1, "interface_label", "plc")
        assert h["10.50.2.20"] == (3, "manual", "engineering_workstation")
        assert h["10.50.2.30"] == (3, "interface_label", "hmi")
        # an ICS client with no level takes the label but keeps its marker (still an unknown device)
        assert h["10.50.1.21"] == (1, "interface_label", "ics_protocol_client_unclassified")
        assert h["10.50.1.1"][1] == "router"                               # infrastructure is never levelled this way

        # relabel port2: the SCADA server follows
        c.post("/topology/set-interface-side", params={"site_id": sid}, json={"interface_id": ifs["port2"], "purdue_level": 3.5})
        assert _hosts(c, sid)["10.50.2.10"] == (3.5, "interface_label", None)
        # clear the label: the level goes with it
        c.post("/topology/set-interface-side", params={"site_id": sid}, json={"interface_id": ifs["port2"], "clear": ["purdue_level"]})
        assert _hosts(c, sid)["10.50.2.10"] == (None, None, None)
        c.post("/topology/set-interface-side", params={"site_id": sid}, json={"interface_id": ifs["port1"], "clear": ["purdue_level"]})
        assert _hosts(c, sid)["10.50.1.21"] == (None, "protocol_client_hint", "ics_protocol_client_unclassified")
        c.post("/topology/set-interface-side", params={"site_id": sid}, json={"interface_id": ifs["port1"], "purdue_level": 1})

        # a declared zone wins over the label
        assert c.post("/subnets", params={"site_id": sid},
                      json={"cidr": "10.50.1.0/24", "purdue_level": 2, "zone_name": "Supervisory"}).status_code == 200
        assert _hosts(c, sid)["10.50.1.200"] == (2, "subnet_declared", None)
        zid = c.get("/subnets", params={"site_id": sid}).json()["subnets"]
        zid = next(z["declaration"]["id"] for z in zid if z["cidr"] == "10.50.1.0/24")
        assert c.delete(f"/subnets/{zid}", params={"site_id": sid}).status_code in (200, 204)
        assert _hosts(c, sid)["10.50.1.200"] == (1, "interface_label", None)

        # the operator's classification replaces the label and survives a relabel
        hid = next(x["id"] for x in c.get("/hosts", params={"site_id": sid, "limit": 5000}).json() if x["ip"] == "10.50.1.200") \
            if isinstance(c.get("/hosts", params={"site_id": sid, "limit": 5000}).json(), list) else None
        if hid is None:
            hs = c.get("/hosts", params={"site_id": sid, "limit": 5000}).json()
            hid = next(x["id"] for x in (hs.get("hosts") or hs.get("items")) if x["ip"] == "10.50.1.200")
        assert c.patch(f"/hosts/{hid}/classification", params={"device_type": "business_workstation", "purdue_level": 4}).status_code == 200
        c.post("/topology/set-interface-side", params={"site_id": sid}, json={"interface_id": ifs["port1"], "purdue_level": 2})
        assert _hosts(c, sid)["10.50.1.200"] == (4, "manual", "business_workstation")


def test_subnet_suggestion_names_the_label(tmp_path):
    with _api(tmp_path / "il2.db") as c:
        sid, ifs = _seed(c)
        rows = {s["cidr"]: s for s in c.get("/subnets", params={"site_id": sid}).json()["subnets"]}
        sug = rows["10.50.2.0/24"]["suggestion"]
        assert sug["purdue_level"] == 3 and any("interface label" in r for r in sug["reasons"])
        assert rows["10.50.3.0/24"]["suggestion"]["purdue_level"] is None or \
            not any("interface label" in r for r in rows["10.50.3.0/24"]["suggestion"]["reasons"])


def test_label_does_not_identify_an_ics_client(tmp_path):
    """An ICS client that only has the interface's level is still an unknown device."""
    from app.parsers.alert_engine import review_unknown_devices
    from app.parsers.site_scope import analysis_site
    from app.models import Finding, NetworkSession
    with _api(tmp_path / "il3.db") as c:
        sid, ifs = _seed(c)
        with c.Session() as s:
            src = s.query(Host).filter(Host.ip == "10.50.1.21").one()
            plc = s.query(Host).filter(Host.ip == "10.50.1.11").one()
            s.add(NetworkSession(src_host_id=src.id, dst_host_id=plc.id, src_port=40000, dst_port=102,
                                 transport="tcp", packet_count=5, protocol="s7comm"))
            src.classification_source, src.purdue_level = "interface_label", 1
            s.commit()
            with analysis_site(s, sid):
                review_unknown_devices(s)
            s.commit()
            titles = [f.title for f in s.query(Finding).filter(Finding.check_name == "unknown_device")]
        assert any("10.50.1.21" in t for t in titles), titles
