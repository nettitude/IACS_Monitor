"""Routed-OT follow-up: automatic levels for the transit to the Internet
firewall and for its Internet leg (app/parsers/edge_links.py)."""
from app.parsers.edge_links import transit_level
from tests.test_cov_routes import _api
from tests.test_rs_span import _FW, _SW, _span_with_internet

# the firewall's default route leaves through wan1 (no FortiOS role set)
_FW_DEFAULT = _FW.replace("config firewall address", """config router static
    edit 1
        set gateway 203.0.113.1
        set device "wan1"
    next
    edit 2
        set dst 10.40.0.0 255.255.0.0
        set gateway 10.40.250.2
        set device "internal"
    next
end
config firewall address""", 1)


def test_transit_level():
    assert transit_level([3, 2, 1, 4, 4, 3]) == 3        # top of the OT stack the core routes
    assert transit_level([1, 2]) == 2
    assert transit_level([4, 4]) == 4                    # an IT-only core: its lowest level
    assert transit_level([3.5, 4]) == 3.5
    assert transit_level([None]) is None and transit_level([]) is None


def _ifaces(c):
    return {i["name"]: i for fw in c.get("/topology/state").json()["firewalls"] for i in fw["interfaces"]}


def _findings(c, check):
    f = c.get("/findings", params={"status": "open", "limit": 5000}).json()
    f = f if isinstance(f, list) else f.get("findings") or f.get("items")
    return [x for x in f if x["check_name"] == check]


def _setup(c, tmp_path, fw=_FW_DEFAULT):
    pc = _span_with_internet(tmp_path)
    assert c.post("/ingest/pcap", files={"file": ("r.pcap", pc.read_bytes(), "application/octet-stream")}).status_code == 200
    assert c.post("/subnets", json={"cidr": "10.40.10.0/24", "purdue_level": 3, "zone_name": "Site ops"}).status_code == 200
    assert c.post("/subnets", json={"cidr": "10.40.30.0/24", "purdue_level": 1, "zone_name": "Control"}).status_code == 200
    assert c.post("/ingest/switch", params={"device_name": "CORE-SW01"},
                  files={"file": ("sw.txt", _SW.encode(), "text/plain")}).status_code == 200
    assert c.post("/ingest/fortigate-config", params={"firewall_name": "FW-INET"},
                  files={"file": ("fw.txt", fw.encode(), "text/plain")}).status_code == 200


def test_edge_levels_make_internet_egress_visible(tmp_path):
    with _api(tmp_path / "e.db") as c:
        _setup(c, tmp_path)
        i = _ifaces(c)
        assert (i["internal"]["purdue_level"], i["internal"]["purdue_suggestion_source"]) == (3, "edge_auto")
        assert (i["wan1"]["purdue_level"], i["wan1"]["purdue_suggestion_source"]) == (5, "edge_auto")
        assert (i["Vlan250"]["purdue_level"], i["Vlan250"]["purdue_suggestion_source"]) == (3, "svi_auto")

        # Subnets & Zones explains the two empty networks
        subs = {s["cidr"]: s for s in c.get("/subnets").json()["subnets"]}
        t = subs["10.40.250.0/30"]["suggestion"]
        assert t["purdue_level"] == 3 and t["zone_name"] == "Transit to FW-INET"
        assert any("transit link" in r for r in t["reasons"])
        w = subs["203.0.113.0/30"]["suggestion"]
        assert w["purdue_level"] == 5 and w["zone_name"] == "Internet (outside FW-INET)"

        # with no interface labelled by hand, egress through switch + firewall is reported
        assert c.post("/reviews/run").status_code == 200
        pe = {x["title"].split(":")[0]: x for x in _findings(c, "path_ot_internet_egress")}
        assert pe["Internet egress from L1"]["severity"] == "critical"
        assert "[seen in capture]" in pe["Internet egress from L1"]["title"]
        # the transit is the core's uplink, not a zone of its own
        assert not any("Vlan250" in x["title"] for x in _findings(c, "switch_routes_between_zones"))

        # an operator label wins and stays
        assert c.post("/topology/set-interface-side",
                      json={"interface_id": i["wan1"]["id"], "purdue_level": 4, "side": "outside"}).status_code == 200
        assert c.post("/reviews/run").status_code == 200
        assert _ifaces(c)["wan1"]["purdue_level"] == 4

        # a declared zone on the transit wins too; removing it brings the automatic level back
        z = c.post("/subnets", json={"cidr": "10.40.250.0/30", "purdue_level": 2, "zone_name": "Transit"}).json()
        i = _ifaces(c)
        assert (i["internal"]["purdue_level"], i["internal"]["purdue_suggestion_source"]) == (2, "zone_declared")
        assert c.delete(f"/subnets/{z['declaration']['id']}").status_code == 200
        i = _ifaces(c)
        assert (i["internal"]["purdue_level"], i["internal"]["purdue_suggestion_source"]) == (3, "edge_auto")


def test_no_default_route_no_internet_leg(tmp_path):
    """Without a default route, WAN role or public range the Internet leg is
    not guessed; the transit still is."""
    with _api(tmp_path / "n.db") as c:
        _setup(c, tmp_path, fw=_FW)
        i = _ifaces(c)
        assert i["internal"]["purdue_suggestion_source"] == "edge_auto"
        assert i["wan1"]["purdue_level"] is None


def test_firewall_without_routing_switch_untouched(tmp_path):
    with _api(tmp_path / "f.db") as c:
        assert c.post("/sites", json={"name": "F", "code": "f"}).status_code in (200, 201)
        assert c.post("/ingest/fortigate-config", params={"firewall_name": "FW-INET", "site": "f"},
                      files={"file": ("fw.txt", _FW_DEFAULT.encode(), "text/plain")}).status_code == 200
        assert c.post("/reviews/run").status_code == 200
        i = _ifaces(c)
        assert i["wan1"]["role"] == "wan"                       # the default route is recorded
        assert i["wan1"]["purdue_level"] is None and i["internal"]["purdue_level"] is None
