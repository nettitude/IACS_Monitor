"""RS G3: operator zones per subnet (GET / POST /subnets, DELETE /subnets/{id})."""
from tests.test_cov_routes import _api
from tests.test_rs_span import _SW, _span_with_internet


def _findings(c, check):
    f = c.get("/findings", params={"status": "open", "limit": 5000}).json()
    f = f if isinstance(f, list) else f.get("findings") or f.get("items")
    return [x for x in f if x["check_name"] == check]


def _host(c, ip):
    hs = c.get("/hosts", params={"limit": 5000}).json()
    hs = hs if isinstance(hs, list) else hs.get("hosts") or hs.get("items")
    return next(h for h in hs if h["ip"] == ip)


def test_subnet_zones(tmp_path):
    with _api(tmp_path / "z.db") as c:
        pc = _span_with_internet(tmp_path)
        up = c.post("/ingest/pcap", files={"file": ("r.pcap", pc.read_bytes(), "application/octet-stream")}).json()
        assert any("subnet(s) have no zone" in n for n in up["upload_notes"])
        d = c.get("/subnets").json()
        by = {s["cidr"]: s for s in d["subnets"]}
        assert by["10.40.10.0/24"]["vlans"] == ["10"] and by["10.40.30.0/24"]["vlans"] == ["30"]
        assert by["10.40.30.0/24"]["suggestion"]["purdue_level"] == 1          # S7 server in it
        assert d["undeclared"] == 2

        # the workstation subnet declared CCTV (L4): its client takes L4
        r = c.post("/subnets", json={"cidr": "10.40.10.7/24", "purdue_level": 4, "zone_name": "CCTV"})
        assert r.status_code == 200 and r.json()["declaration"]["cidr"] == "10.40.10.0/24"
        a = _host(c, "10.40.10.10")
        assert (a["purdue_level"], a["classification_source"]) == (4, "subnet_declared")
        node = next(n for n in c.get("/topology").json()["nodes"] if n["ip"] == "10.40.10.10")
        assert node["zone"] == {"cidr": "10.40.10.0/24", "name": "CCTV", "purdue_level": 4}
        assert c.get("/subnets").json()["undeclared"] == 1

        # the PLC subnet wrongly declared L4: the PLC keeps L1 and is reported
        z = c.post("/subnets", json={"cidr": "10.40.30.0/24", "purdue_level": 4, "zone_name": "IT"}).json()
        p = _host(c, "10.40.30.10")
        assert p["purdue_level"] == 1 and p["classification_source"] == "protocol_inferred"
        assert c.post("/reviews/run").status_code == 200
        mis = [x for x in _findings(c, "misplaced_device") if x["detail"].get("basis") == "subnet zone declaration"]
        assert [(x["detail"]["ip"], x["severity"]) for x in mis] == [("10.40.30.10", "high")]
        row = next(s for s in c.get("/subnets").json()["subnets"] if s["cidr"] == "10.40.30.0/24")
        assert row["mismatched_devices"][0]["ip"] == "10.40.30.10"

        # correct it: no mismatch at the next review
        c.post("/subnets", json={"cidr": "10.40.30.0/24", "purdue_level": 1, "zone_name": "Control"})
        assert c.post("/reviews/run").status_code == 200
        assert not [x for x in _findings(c, "misplaced_device") if x["detail"].get("basis") == "subnet zone declaration"]

        # switch config: SVIs on declared subnets take the zone level
        assert c.post("/ingest/switch", params={"device_name": "CORE-SW01"},
                      files={"file": ("sw.txt", _SW.encode(), "text/plain")}).status_code == 200
        ifs = {i["name"]: i for fw in c.get("/topology/state").json()["firewalls"] for i in fw["interfaces"]}
        assert ifs["Vlan10"]["purdue_level"] == 4 and ifs["Vlan30"]["purdue_level"] == 1
        sw = _findings(c, "switch_routes_between_zones")
        assert c.post("/reviews/run").status_code == 200
        sw = _findings(c, "switch_routes_between_zones")
        t = {x["detail"]["svi"]: x for x in sw}
        # L1 routed to an L4 VLAN: critical; plus the unlabelled transit VLAN
        assert t["Vlan30"]["severity"] == "critical" and t["Vlan30"]["detail"]["unlabelled"]

        # clearing the zone puts the hosts back to automatic
        zid = next(s for s in c.get("/subnets").json()["subnets"] if s["cidr"] == "10.40.10.0/24")["declaration"]["id"]
        assert c.delete(f"/subnets/{zid}").status_code == 200
        a = _host(c, "10.40.10.10")
        assert a["classification_source"] != "subnet_declared" and a["purdue_level"] is None
        assert z["declaration"]["purdue_level"] == 4


def test_subnet_zone_errors(tmp_path):
    with _api(tmp_path / "e.db") as c:
        assert c.post("/sites", json={"name": "Z", "code": "z"}).status_code in (200, 201)
        assert c.post("/subnets", json={"cidr": "nonsense", "purdue_level": 1}).status_code == 422
        assert c.post("/subnets", json={"cidr": "0.0.0.0/0", "purdue_level": 1}).status_code == 422
        assert c.post("/subnets", json={"cidr": "10.0.0.0/24", "purdue_level": 9}).status_code == 422
        assert c.delete("/subnets/999").status_code == 404
        assert c.get("/subnets").json()["subnets"] == []
