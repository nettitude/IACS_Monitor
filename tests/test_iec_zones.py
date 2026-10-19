"""IEC 62443-3-2 zones and conduits (app/iec_zones.py, /iec-zones, /iec-conduits).

Zones are documentation: they may span Purdue levels and address ranges,
an asset belongs to one zone, conduits show the policies and traffic
between zones, and nothing here changes findings."""
import csv
import io
from datetime import datetime, timezone

from app.models import (Finding, Firewall, FirewallInterface, FirewallRule, FirewallZoneDef, Host,
                        NetworkSession, Site)
from tests.test_cov_routes import _api

NOW = datetime.now(timezone.utc)


def _seed(c):
    with c.Session() as s:
        site = Site(name="Plant", code="p")
        s.add(site)
        s.flush()
        fw = Firewall(name="FW-SITE", device_name="FW-SITE", vendor="fortigate", site_id=site.id)
        s.add(fw)
        s.flush()

        def iface(name, net, level, **kw):
            ip = net.replace(".0/24", ".1")
            s.add(FirewallInterface(firewall_id=fw.id, name=name, ip_address=ip, prefix_len=24,
                                    ip_cidr=f"{ip}/24", network_cidr=net, purdue_level=level, **kw))
        iface("port1", "10.50.1.0/24", 1)
        iface("port2", "10.50.2.0/24", 3)
        iface("port3", "10.50.3.0/24", 4)
        iface("port4", "10.50.4.0/24", 3.5)
        iface("port1.20", "10.50.20.0/24", 2, iface_type="vlan", vlan_id="20")       # VLAN sub-interface
        s.add(FirewallZoneDef(firewall_id=fw.id, vdom="root", name="CONTROL", members=["port1", "port1.20"]))
        s.flush()

        def host(ip, mac, level=None, dt=None):
            h = Host(ip=ip, mac=mac, site_id=site.id, first_seen=NOW, last_seen=NOW, sources=["pcap"],
                     purdue_level=level, device_type=dt, classification_source="manual" if dt else None)
            s.add(h)
            s.flush()
            return h
        plc = host("10.50.1.11", "00:00:00:00:01:0b", 1, "plc")
        hmi = host("10.50.20.21", "00:00:00:00:14:15", 2, "hmi")
        scada = host("10.50.2.10", "00:00:00:00:02:0a", 3, "site_scada_server")
        ews = host("10.50.2.20", "00:00:00:00:02:14", 3, "engineering_workstation")
        hist = host("10.50.3.10", "00:00:00:00:03:0a", 4, "historian")
        jump = host("10.50.4.10", "00:00:00:00:04:0a", 3.5, "jump_host")
        inet = host("52.10.20.30", None)

        def sess(a, b, port, proto="unknown"):
            s.add(NetworkSession(src_host_id=a.id, dst_host_id=b.id, src_port=40000 + port % 1000, dst_port=port,
                                 transport="tcp", packet_count=10, protocol=proto, last_seen=NOW))
        sess(scada, hmi, 4840)            # site ops -> control zone (L3 -> L2)
        sess(ews, plc, 102, "s7comm")     # engineering -> controllers
        sess(hist, scada, 4840)           # L4 -> L3
        sess(jump, plc, 102, "s7comm")    # DMZ -> controllers
        sess(scada, inet, 443)            # to the Internet
        sess(hmi, plc, 502, "modbus")     # inside the control zone

        def rule(pid, sz, dz, src="all", dst="all", port="any", proto="tcp"):
            s.add(FirewallRule(site_id=site.id, firewall_id=fw.id, device_name="FW-SITE", device_type="fortigate",
                               policy_id=pid, vdom="root", src_zone=sz, dst_zone=dz, src=src, dst=dst,
                               protocol=proto, dst_port=port, action="accept", enabled=True))
        rule("3", "port4", "CONTROL", src="10.50.4.10/32", port="102")
        rule("5", "port3", "port2", port="4840")
        rule("12", "port2", "CONTROL", port="any", proto="any")
        rule("8", "port2", "port5", src="10.50.2.10/32", port="443")
        s.commit()
        return site.id


def _rows(r):
    return list(csv.DictReader(io.StringIO(r.content.decode("utf-8-sig"))))


def test_zones_span_levels_and_networks(tmp_path):
    with _api(tmp_path / "z.db") as c:
        sid = _seed(c)
        P = {"site_id": sid}
        # a "Control" zone: the FortiGate zone CONTROL (port1 L1 + VLAN port1.20 L2)
        ctl = c.post("/iec-zones", params=P, json={"name": "Control", "sl_t": 3}).json()["zone"]
        assert c.post(f"/iec-zones/{ctl['id']}/members", params=P,
                      json={"kind": "fw_zone", "ref": "FW-SITE/CONTROL"}).status_code == 200
        # an "Operations" zone spanning L3 and the L4 historian - by subnet and by host
        ops = c.post("/iec-zones", params=P, json={"name": "Operations", "sl_t": 2}).json()["zone"]
        assert c.post(f"/iec-zones/{ops['id']}/members", params=P, json={"kind": "subnet", "ref": "10.50.2.7/24"}).json()["member"]["ref"] == "10.50.2.0/24"
        assert c.post(f"/iec-zones/{ops['id']}/members", params=P, json={"kind": "host", "ref": "00-00-00-00-03-0A"}).json()["member"]["ref"] == "mac:00:00:00:00:03:0a"
        # the DMZ by interface
        dmz = c.post("/iec-zones", params=P, json={"name": "Vendor DMZ", "sl_t": "SL-T 3"}).json()["zone"]
        assert dmz["sl_t"] == 3
        assert c.post(f"/iec-zones/{dmz['id']}/members", params=P, json={"kind": "interface", "ref": "FW-SITE/port4"}).status_code == 200

        d = c.get("/iec-zones", params=P).json()
        z = {x["name"]: x for x in d["zones"]}
        assert z["Control"]["purdue_levels"] == [1.0, 2.0]
        assert sorted(h["ip"] for h in z["Control"]["hosts"]) == ["10.50.1.11", "10.50.20.21"]
        assert z["Operations"]["purdue_levels"] == [3.0, 4.0]          # one zone, two levels, two networks
        hist = next(h for h in z["Operations"]["hosts"] if h["ip"] == "10.50.3.10")
        assert hist["basis"].startswith("host member")
        assert [h["ip"] for h in z["Vendor DMZ"]["hosts"]] == ["10.50.4.10"]
        assert all(m["found"] for x in d["zones"] for m in x["members"])
        assert [h["ip"] for h in d["unassigned_hosts"]] == []            # Internet address is not "unassigned"

        # an asset in several zones is never refused (owner): it is listed and reported as a finding
        r = c.post(f"/iec-zones/{dmz['id']}/members", params=P, json={"kind": "host", "ref": "00:00:00:00:03:0a"})
        assert r.status_code == 200 and r.json()["changed"]
        d2 = c.get("/iec-zones", params=P).json()
        mz = d2["multi_zone_hosts"]
        assert len(mz) == 1 and mz[0]["addresses"] == ["10.50.3.10"] and {z["name"] for z in mz[0]["zones"]} == {"Operations", "Vendor DMZ"}
        # 'move' relocates every placement into one zone
        r = c.post(f"/iec-zones/{dmz['id']}/members", params=P,
                   json={"kind": "host", "ref": "00:00:00:00:03:0a", "move": True})
        assert r.status_code == 200
        d2 = c.get("/iec-zones", params=P).json()
        assert d2["multi_zone_hosts"] == []
        z = {x["name"]: x for x in d2["zones"]}
        assert "10.50.3.10" in [h["ip"] for h in z["Vendor DMZ"]["hosts"]] and "10.50.3.10" not in [h["ip"] for h in z["Operations"]["hosts"]]
        # bad input
        assert c.post(f"/iec-zones/{dmz['id']}/members", params=P, json={"kind": "vlan", "ref": "20"}).status_code == 422
        assert c.post(f"/iec-zones/{dmz['id']}/members", params=P, json={"kind": "host", "ref": "nope"}).status_code == 422
        assert c.post("/iec-zones", params=P, json={"name": "Control"}).status_code == 409
        assert c.post("/iec-zones", params=P, json={"name": "X", "sl_t": 5}).status_code == 422
        # a member that no longer resolves is shown, not dropped
        c.post(f"/iec-zones/{dmz['id']}/members", params=P, json={"kind": "interface", "ref": "FW-SITE/port9"})
        mem = [m for m in c.get("/iec-zones", params=P).json()["zones"] if m["name"] == "Vendor DMZ"][0]["members"]
        assert any(m["ref"] == "FW-SITE/port9" and not m["found"] for m in mem)

        cand = c.get("/iec-zones/candidates", params=P).json()
        assert {"FW-SITE/port1.20", "FW-SITE/port4"} <= {i["ref"] for i in cand["interfaces"]}
        assert next(i for i in cand["interfaces"] if i["ref"] == "FW-SITE/port4")["zone"] == "Vendor DMZ"
        assert cand["fw_zones"][0]["ref"] == "FW-SITE/root/CONTROL"


def test_conduits_policies_traffic_and_undocumented_pairs(tmp_path):
    with _api(tmp_path / "c.db") as c:
        sid = _seed(c)
        P = {"site_id": sid}
        ids = {}
        for name, kind, ref in (("Control", "fw_zone", "FW-SITE/CONTROL"), ("Operations", "subnet", "10.50.2.0/24"),
                                ("Enterprise", "interface", "FW-SITE/port3"), ("Vendor DMZ", "interface", "FW-SITE/port4")):
            ids[name] = c.post("/iec-zones", params=P, json={"name": name, "sl_t": 3 if name == "Control" else 2}).json()["zone"]["id"]
            c.post(f"/iec-zones/{ids[name]}/members", params=P, json={"kind": kind, "ref": ref})
        # document the DMZ -> Control conduit only, at a lower SL-T than Control
        r = c.post("/iec-conduits", params=P, json={"zone_a_id": ids["Control"], "zone_b_id": ids["Vendor DMZ"],
                                                    "name": "Vendor programming", "sl_t": 2})
        assert r.status_code == 200 and r.json()["created"]
        v = c.get("/iec-conduits", params=P).json()
        (cd,) = v["conduits"]
        assert cd["name"] == "Vendor programming"
        names = {cd["zone_a"]["name"]: "a", cd["zone_b"]["name"]: "b"}
        d = cd["a_to_b"] if names["Vendor DMZ"] == "a" else cd["b_to_a"]
        assert d["sessions"] == 1 and d["policies"][0]["policy"] == "FW-SITE policy 3 (vdom root)"
        assert any("below the zones it connects" in n for n in cd["notes"])
        und = {(u["zone_a"]["name"], u["zone_b"]["name"]): u for u in v["undocumented"]}
        key = next(k for k in und if set(k) == {"Control", "Operations"})
        assert und[key]["declarable"] and und[key]["sessions"] == 2 and und[key]["policy_count"] >= 1
        assert any(set(k) == {"Operations", "External / Internet"} for k in und)
        assert any(set(k) == {"Enterprise", "Operations"} for k in und)
        assert v["intra_zone"][0]["zone"]["name"] == "Control" and v["intra_zone"][0]["sessions"] == 1
        # a conduit with nothing behind it says so
        c.post("/iec-conduits", params=P, json={"zone_a_id": ids["Enterprise"], "zone_b_id": ids["Vendor DMZ"]})
        empty = next(x for x in c.get("/iec-conduits", params=P).json()["conduits"]
                     if {x["zone_a"]["name"], x["zone_b"]["name"]} == {"Enterprise", "Vendor DMZ"})
        assert any("no permitting policy and no traffic" in n for n in empty["notes"])
        assert c.post("/iec-conduits", params=P, json={"zone_a_id": ids["Control"], "zone_b_id": ids["Control"]}).status_code == 422

        # CSV exports
        z = _rows(c.get("/iec-zones/export", params={**P, "table": "zones"}))
        assert {r["zone"] for r in z} == set(ids)
        assert any(r["member"] == "FW-SITE//CONTROL" and r["member_kind"] == "fw_zone" for r in z)
        ctl = next(r for r in z if r["zone"] == "Control")
        assert ctl["purdue_levels"] == "L1 L2" and ctl["host_count"] == "2"
        a = {r["ip"]: r for r in _rows(c.get("/iec-zones/export", params={**P, "table": "assets"}))}
        assert a["10.50.20.21"]["zone"] == "Control" and a["10.50.20.21"]["sl_t"] == "3"
        cn = _rows(c.get("/iec-zones/export", params={**P, "table": "conduits"}))
        assert any(r["conduit"] == "Vendor programming" and r["documented"] == "yes" for r in cn)
        assert any(r["documented"] == "no" and r["to_zone"] == "External / Internet" for r in cn)
        assert c.get("/iec-zones/export", params={**P, "table": "nope"}).status_code == 422

        # deleting a zone removes its members and conduits
        assert c.delete(f"/iec-zones/{ids['Vendor DMZ']}", params=P).status_code == 200
        assert not [x for x in c.get("/iec-conduits", params=P).json()["conduits"]
                    if "Vendor DMZ" in (x["zone_a"]["name"], x["zone_b"]["name"])]


def test_import_from_subnet_zones_and_fortigate(tmp_path):
    with _api(tmp_path / "i.db") as c:
        sid = _seed(c)
        P = {"site_id": sid}
        c.post("/subnets", params=P, json={"cidr": "10.50.2.0/24", "purdue_level": 3, "zone_name": "Site ops"})
        c.post("/subnets", params=P, json={"cidr": "10.50.3.0/24", "purdue_level": 4, "zone_name": "Site ops"})
        r = c.post("/iec-zones/import", params=P, json={"source": "subnet_zones"}).json()["imported"]
        assert r == {"zones_created": 1, "members_added": 2, "members_skipped": 0}
        r = c.post("/iec-zones/import", params=P, json={"source": "fortigate"}).json()["imported"]
        assert r["zones_created"] == 1 and r["members_added"] == 1
        again = c.post("/iec-zones/import", params=P, json={"source": "fortigate"}).json()["imported"]
        assert again == {"zones_created": 0, "members_added": 0, "members_skipped": 1}
        z = {x["name"]: x for x in c.get("/iec-zones", params=P).json()["zones"]}
        assert z["Site ops"]["purdue_levels"] == [3.0, 4.0] and z["CONTROL"]["host_count"] == 2
        assert c.post("/iec-zones/import", params=P, json={"source": "x"}).status_code == 422


def test_zones_never_change_findings(tmp_path):
    """The same review run gives the same findings with and without zones -
    except the one check sourced from the zone documentation itself
    (undocumented_conduit, owner decision 2026-10-11)."""
    def snapshot(c, sid):
        assert c.post("/reviews/run", params={"site_id": sid}).status_code == 200
        with c.Session() as s:
            return sorted((f.check_name, f.title, f.severity, f.status) for f in s.query(Finding)
                          if f.check_name not in ("undocumented_conduit", "host_in_multiple_zones", "network_in_multiple_zones"))

    with _api(tmp_path / "a.db") as c:
        sid = _seed(c)
        before = snapshot(c, sid)
    with _api(tmp_path / "b.db") as c:
        sid = _seed(c)
        P = {"site_id": sid}
        zid = c.post("/iec-zones", params=P, json={"name": "Everything", "sl_t": 1}).json()["zone"]["id"]
        for kind, ref in (("fw_zone", "FW-SITE/CONTROL"), ("subnet", "10.50.2.0/24"), ("interface", "FW-SITE/port3"),
                          ("host", "10.50.4.10")):
            c.post(f"/iec-zones/{zid}/members", params=P, json={"kind": kind, "ref": ref})
        z2 = c.post("/iec-zones", params=P, json={"name": "Other", "sl_t": 4}).json()["zone"]["id"]
        c.post("/iec-conduits", params=P, json={"zone_a_id": zid, "zone_b_id": z2, "sl_t": 1})
        with c.Session() as s:
            hosts_before = sorted((h.ip, h.purdue_level, h.classification_source, h.device_type) for h in s.query(Host))
        after = snapshot(c, sid)
        with c.Session() as s:
            hosts_after = sorted((h.ip, h.purdue_level, h.classification_source, h.device_type) for h in s.query(Host))
    assert after == before and before
    assert hosts_after == hosts_before


def test_engine_does_not_import_the_zone_module():
    """The engine (parsers, explanations) never sees zones, with one named
    exception: app/zone_findings.py, the module of the undocumented_conduit
    check, which alert_engine runs as a periodic review.  The report uses
    zones only in its own section and the view-time SL-T judgement
    (collect_zone_data), never while collecting the findings."""
    import ast
    import pathlib
    root = pathlib.Path(__file__).resolve().parents[1]
    for p in list((root / "app" / "parsers").glob("*.py")) + [root / "app" / "explain.py"]:
        assert "iec_zones" not in p.read_text(), p
        if p.name != "alert_engine.py":
            assert "zone_findings" not in p.read_text(), p
    ae = (root / "app" / "parsers" / "alert_engine.py").read_text()
    assert ae.count("zone_findings") == 2 and "_zf.review_undocumented_conduits" in ae
    src = (root / "generate_report.py").read_text()
    tree = ast.parse(src)
    allowed = [n for n in tree.body if isinstance(n, ast.FunctionDef) and n.name == "collect_zone_data"]
    assert len(allowed) == 1
    lo, hi = allowed[0].lineno, allowed[0].end_lineno
    lines = [i for i, line in enumerate(src.splitlines(), start=1) if "iec_zones" in line]
    assert lines and all(lo <= i <= hi for i in lines), lines


def test_site_delete_purges_zones(tmp_path, monkeypatch):
    monkeypatch.setenv("IACS_ENABLE_DELETE", "true")
    with _api(tmp_path / "d.db") as c:
        sid = _seed(c)
        P = {"site_id": sid}
        a = c.post("/iec-zones", params=P, json={"name": "A"}).json()["zone"]["id"]
        b = c.post("/iec-zones", params=P, json={"name": "B"}).json()["zone"]["id"]
        c.post(f"/iec-zones/{a}/members", params=P, json={"kind": "subnet", "ref": "10.50.1.0/24"})
        c.post("/iec-conduits", params=P, json={"zone_a_id": a, "zone_b_id": b})
        monkeypatch.setenv("IACS_ENABLE_DELETE", "true")          # _api clears it on entry
        assert c.post("/sites", json={"name": "Other", "code": "o"}).status_code in (200, 201)
        r = c.delete(f"/sites/{sid}", params={"force": "true"})
        assert r.status_code in (200, 204), r.text
        from app.models import IecConduit, IecZone, IecZoneMember
        with c.Session() as s:
            assert s.query(IecZone).count() == 0 and s.query(IecZoneMember).count() == 0 and s.query(IecConduit).count() == 0


def test_zone_and_conduit_edits(tmp_path):
    with _api(tmp_path / "e.db") as c:
        sid = _seed(c)
        P = {"site_id": sid}
        a = c.post("/iec-zones", params=P, json={"name": "A", "sl_t": 1}).json()["zone"]["id"]
        b = c.post("/iec-zones", params=P, json={"name": "B"}).json()["zone"]["id"]
        r = c.patch(f"/iec-zones/{a}", params=P, json={"name": "Control cell 1", "sl_t": "SL3",
                                                        "description": "PLCs and HMIs", "owner": "OT eng"})
        assert r.status_code == 200 and r.json()["zone"] == {"id": a, "name": "Control cell 1", "sl_t": 3,
                                                               "sl_a": None, "sl_a_note": None,
                                                               "description": "PLCs and HMIs", "owner": "OT eng"}
        assert c.patch(f"/iec-zones/{a}", params=P, json={"name": "B"}).status_code == 409
        assert c.patch(f"/iec-zones/{a}", params=P, json={"sl_t": None}).json()["zone"]["sl_t"] is None
        assert c.patch("/iec-zones/9999", params=P, json={"name": "x"}).status_code == 404
        m = c.post(f"/iec-zones/{a}/members", params=P, json={"kind": "subnet", "ref": "10.50.1.0/24"}).json()["member"]
        assert c.delete(f"/iec-zones/members/{m['id']}", params=P).status_code == 200
        assert c.delete(f"/iec-zones/members/{m['id']}", params=P).status_code == 404
        cd = c.post("/iec-conduits", params=P, json={"zone_a_id": b, "zone_b_id": a}).json()["conduit"]
        assert (cd["zone_a_id"], cd["zone_b_id"]) == (min(a, b), max(a, b))      # stored per pair
        r = c.patch(f"/iec-conduits/{cd['id']}", params=P, json={"name": "Cell uplink", "sl_t": 2})
        assert r.json()["conduit"]["name"] == "Cell uplink" and r.json()["conduit"]["sl_t"] == 2
        assert c.patch(f"/iec-conduits/{cd['id']}", params=P, json={"sl_t": 7}).status_code == 422
        assert c.delete(f"/iec-conduits/{cd['id']}", params=P).status_code == 200
        assert c.delete(f"/iec-conduits/{cd['id']}", params=P).status_code == 404


# ------------------------------------------------- SL-C and the CSV zone column --

def _host_id(c, sid, ip):
    hs = c.get("/hosts", params={"site_id": sid, "limit": 5000}).json()
    hs = hs if isinstance(hs, list) else hs.get("hosts") or hs.get("items")
    return next(h["id"] for h in hs if h["ip"] == ip)


def test_sl_c_on_hosts_zones_and_conduit_firewalls(tmp_path):
    with _api(tmp_path / "slc.db") as c:
        sid = _seed(c)
        P = {"site_id": sid}
        ctl = c.post("/iec-zones", params=P, json={"name": "Control", "sl_t": 3}).json()["zone"]["id"]
        dmz = c.post("/iec-zones", params=P, json={"name": "DMZ", "sl_t": 2}).json()["zone"]["id"]
        c.post(f"/iec-zones/{ctl}/members", params=P, json={"kind": "fw_zone", "ref": "FW-SITE/CONTROL"})
        c.post(f"/iec-zones/{dmz}/members", params=P, json={"kind": "interface", "ref": "FW-SITE/port4"})
        plc, hmi = _host_id(c, sid, "10.50.1.11"), _host_id(c, sid, "10.50.20.21")
        # host SL-C through the inventory API
        r = c.patch(f"/assets/{plc}", params={"sl_c": "SL-C 1", "sl_c_source": "vendor statement 2024"})
        assert r.status_code == 200 and (r.json()["sl_c"], r.json()["sl_c_source"]) == (1, "vendor statement 2024")
        assert c.patch(f"/assets/{hmi}", params={"sl_c": "3"}).json()["sl_c"] == 3
        assert c.patch(f"/assets/{hmi}", params={"sl_c": "5"}).status_code == 422
        z = {x["name"]: x for x in c.get("/iec-zones", params=P).json()["zones"]}["Control"]
        assert z["sl_c"]["assessed"] == 2 and z["sl_c"]["min"] == 1
        assert [b["ip"] for b in z["sl_c"]["below_target"]] == ["10.50.1.11"]
        assert any("below the zone's SL-T 3" in n for n in z["sl_c"]["notes"])
        assert next(h for h in z["hosts"] if h["ip"] == "10.50.1.11")["below_target"] is True
        # clearing
        assert c.patch(f"/assets/{hmi}", params={"sl_c": "none"}).json()["sl_c"] is None
        z = {x["name"]: x for x in c.get("/iec-zones", params=P).json()["zones"]}["Control"]
        assert any("have no SL-C recorded" in n for n in z["sl_c"]["notes"])

        # firewall SL-C against the conduit it carries
        c.post("/iec-conduits", params=P, json={"zone_a_id": ctl, "zone_b_id": dmz, "name": "Vendor", "sl_t": 3})
        fw_id = c.get("/iec-conduits", params=P).json()["devices"][0]["id"]
        r = c.patch(f"/firewalls/{fw_id}/sl-c", params=P, json={"sl_c": 2, "sl_c_source": "FortiGate IEC 62443-4-2 cert"})
        assert r.status_code == 200 and r.json()["firewall"]["sl_c"] == 2
        v = c.get("/iec-conduits", params=P).json()
        (cd,) = v["conduits"]
        assert cd["target_sl"] == 3 and cd["firewalls"][0]["sl_c"] == 2
        assert any("carries this conduit with SL-C 2, below its target SL-T 3" in n for n in cd["notes"])
        dev = v["devices"][0]
        assert dev["below_target"] and dev["highest_target"] == 3 and dev["conduits"][0]["conduit"] == "Vendor"
        assert c.patch(f"/firewalls/{fw_id}/sl-c", params=P, json={"sl_c": 9}).status_code == 422
        assert c.patch("/firewalls/9999/sl-c", params=P, json={"sl_c": 1}).status_code == 404
        # exports
        a = {r["ip"]: r for r in _rows(c.get("/iec-zones/export", params={**P, "table": "assets"}))}
        assert (a["10.50.1.11"]["sl_c"], a["10.50.1.11"]["sl_c_below_sl_t"]) == ("1", "yes")
        cn = _rows(c.get("/iec-zones/export", params={**P, "table": "conduits"}))
        assert any("FW-SITE=SL-C2" in r["firewalls_sl_c"] for r in cn if r["conduit"] == "Vendor")
        zr = _rows(c.get("/iec-zones/export", params={**P, "table": "zones"}))
        assert any(r["zone"] == "Control" and r["sl_c_below_target"] == "10.50.1.11=SL-C1" for r in zr)
        inv = list(csv.DictReader(io.StringIO(c.get("/assets/export", params=P).content.decode("utf-8-sig"))))
        assert next(r for r in inv if r["ip"] == "10.50.1.11")["sl_c"] == "1"


def test_inventory_csv_sets_sl_c_and_zone(tmp_path):
    with _api(tmp_path / "inv.db") as c:
        sid = _seed(c)
        P = {"site_id": sid}
        other = c.post("/iec-zones", params=P, json={"name": "Elsewhere"}).json()["zone"]["id"]
        c.post(f"/iec-zones/{other}/members", params=P, json={"kind": "host", "ref": "00:00:00:00:02:14"})
        body = ("ip,mac,hostname,zone,sl_c,sl_c_source\n"
                "10.50.1.11,00:00:00:00:01:0b,PLC-01,Control cell,SL2,TÜV cert 1234\n"
                "10.50.20.21,,HMI-01,Control cell,3,\n"
                "10.50.2.20,,EWS,Control cell,x,\n"              # already in another zone, bad SL-C
                "10.50.9.9,,NEW,Control cell,,\n").encode()
        r = c.post("/ingest/baseline/asset-inventory", params={"site": "p", "baseline_name": "inv"},
                   files={"file": ("inv.csv", body, "text/csv")})
        assert r.status_code == 200, r.text
        st = r.json()["stats"]
        assert st["zones_created"] == ["Control cell"] and st["zone_members_added"] == 4
        assert st["sl_c_set"] == 2 and st["invalid_sl_c"] == 1
        assert len(st["zone_multi"]) == 1 and "Elsewhere" in st["zone_multi"][0]
        d = c.get("/iec-zones", params=P).json()
        z = {x["name"]: x for x in d["zones"]}
        assert sorted(h["ip"] for h in z["Control cell"]["hosts"]) == ["10.50.1.11", "10.50.2.20", "10.50.20.21", "10.50.9.9"]
        assert [h["ip"] for h in z["Elsewhere"]["hosts"]] == ["10.50.2.20"]          # added, not moved: in both
        assert [m["addresses"] for m in d["multi_zone_hosts"]] == [["10.50.2.20"]]
        plc = next(h for h in z["Control cell"]["hosts"] if h["ip"] == "10.50.1.11")
        assert (plc["sl_c"], plc["sl_c_source"]) == (2, "TÜV cert 1234")
        assert all(m["ref"].startswith("mac:") or m["ref"].startswith("ip:") for m in z["Control cell"]["members"])
        # re-import: idempotent
        r2 = c.post("/ingest/baseline/asset-inventory", params={"site": "p", "baseline_name": "inv"},
                    files={"file": ("inv.csv", body, "text/csv")}).json()["stats"]
        assert r2["zone_members_added"] == 0 and r2["zone_already"] == 4 and r2["zones_created"] == []


def test_sl_c_never_changes_findings(tmp_path):
    def snapshot(c, sid):
        assert c.post("/reviews/run", params={"site_id": sid}).status_code == 200
        with c.Session() as s:
            return sorted((f.check_name, f.title, f.severity, f.status) for f in s.query(Finding)
                          if f.check_name not in ("undocumented_conduit", "host_in_multiple_zones", "network_in_multiple_zones"))
    with _api(tmp_path / "a.db") as c:
        before = snapshot(c, _seed(c))
    with _api(tmp_path / "b.db") as c:
        sid = _seed(c)
        with c.Session() as s:
            for h in s.query(Host):
                h.sl_c, h.sl_c_source = 1, "x"
            for f in s.query(Firewall):
                f.sl_c = 1
            s.commit()
        after = snapshot(c, sid)
    assert after == before and before


# ------------------------------------------------------------------ SL-A --
def test_sl_a_on_zones_and_conduits(tmp_path):
    with _api(tmp_path / "sla.db") as c:
        sid = _seed(c)
        P = {"site_id": sid}
        r = c.post("/iec-zones", params=P, json={"name": "Control", "sl_t": 3, "sl_a": 2, "sl_a_note": "assessment 2026-09"})
        assert r.status_code == 200, r.text
        za = r.json()["zone"]
        assert (za["sl_a"], za["sl_a_note"]) == (2, "assessment 2026-09")
        zb = c.post("/iec-zones", params=P, json={"name": "Ops", "sl_t": 2}).json()["zone"]
        assert c.post("/iec-zones", params=P, json={"name": "Bad", "sl_a": 7}).status_code == 422
        assert c.patch(f"/iec-zones/{zb['id']}", params=P, json={"sl_a": "SL-A 3"}).json()["zone"]["sl_a"] == 3
        assert c.patch(f"/iec-zones/{zb['id']}", params=P, json={"sl_a": 9}).status_code == 422
        zones = {z["name"]: z for z in c.get("/iec-zones", params=P).json()["zones"]}
        assert zones["Control"]["sl_a_status"] == "below" and zones["Ops"]["sl_a_status"] == "meets"
        c.patch(f"/iec-zones/{zb['id']}", params=P, json={"sl_a": None})
        assert {z["name"]: z for z in c.get("/iec-zones", params=P).json()["zones"]}["Ops"]["sl_a_status"] == "not_assessed"

        cd = c.post("/iec-conduits", params=P, json={"zone_a_id": za["id"], "zone_b_id": zb["id"], "name": "Sup",
                                                     "sl_a": 1, "sl_a_note": "pen test"}).json()["conduit"]
        assert (cd["sl_a"], cd["sl_a_note"]) == (1, "pen test")
        row = c.get("/iec-conduits", params=P).json()["conduits"][0]
        assert row["target_sl"] == 3 and row["sl_a_status"] == "below"
        assert any("achieved SL-A 1 is below the target SL-T 3" in n for n in row["notes"])
        assert c.patch(f"/iec-conduits/{cd['id']}", params=P, json={"sl_a": 3}).json()["conduit"]["sl_a"] == 3
        assert c.get("/iec-conduits", params=P).json()["conduits"][0]["sl_a_status"] == "meets"

        zr = {r["zone"]: r for r in _rows(c.get("/iec-zones/export", params={**P, "table": "zones"}))}
        assert zr["Control"]["sl_a"] == "2" and zr["Control"]["sl_a_status"] == "below"
        assert zr["Control"]["sl_a_note"] == "assessment 2026-09"
        cr = _rows(c.get("/iec-zones/export", params={**P, "table": "conduits"}))
        assert cr[0]["sl_a"] == "3" and cr[0]["sl_a_status"] == "meets"


# ------------------------------------------- findings judged against SL-T --
def _judge_seed(c):
    """Zones on the _seed site plus findings with known devices and SRs."""
    sid = _seed(c)
    P = {"site_id": sid}
    ctl = c.post("/iec-zones", params=P, json={"name": "Control", "sl_t": 2}).json()["zone"]["id"]
    ops = c.post("/iec-zones", params=P, json={"name": "Ops", "sl_t": 3}).json()["zone"]["id"]
    dmz = c.post("/iec-zones", params=P, json={"name": "DMZ"}).json()["zone"]["id"]        # no SL-T
    c.post(f"/iec-zones/{ctl}/members", params=P, json={"kind": "fw_zone", "ref": "FW-SITE/CONTROL"})
    c.post(f"/iec-zones/{ops}/members", params=P, json={"kind": "interface", "ref": "FW-SITE/port2"})
    c.post(f"/iec-zones/{dmz}/members", params=P, json={"kind": "subnet", "ref": "10.50.4.0/24"})
    c.post("/iec-conduits", params=P, json={"zone_a_id": ctl, "zone_b_id": ops, "name": "Supervisory", "sl_t": 4})
    ent = c.post("/iec-zones", params=P, json={"name": "Enterprise", "sl_t": 1}).json()["zone"]["id"]
    c.post(f"/iec-zones/{ent}/members", params=P, json={"kind": "host", "ref": "00:00:00:00:03:0a"})   # the historian
    ids = {}
    with c.Session() as s:
        def add(key, check, sr, sev, **detail):
            f = Finding(site_id=sid, category="periodic_review", check_name=check, severity=sev, status="open",
                        isa62443_sr=sr, title=key, detail=detail, device_name=detail.pop("_dev", None),
                        source_ref=key)
            s.add(f)
            s.flush()
            ids[key] = f.id
        add("plc-sl1", "x_check", "SR 2.1", "high", src_ip="10.50.1.11")                    # SL1 in Control (SL-T 2)
        add("plc-sl3", "y_check", "SR 5.1 RE2", "medium", ot_host_ip="10.50.1.11")          # SL3 in Control -> beyond
        add("pair", "z_check", "SR 5.1 RE2", "low", src_ip="10.50.2.10", dst_ip="10.50.1.11")   # conduit SL-T 4
        add("dmz", "z_check", "SR 3.3", "low", src_ip="10.50.4.10")                         # zone without SL-T
        add("nozone", "z_check", "SR 3.3", "low", src_ip="10.50.3.20")                      # port3 network: no zone
        add("egress", "session_ot_internet_egress", "SR 5.1 RE2", "critical",
            src_ip="10.50.1.11", dst_ip="8.8.8.8")                                          # owner rule
        add("policy", "config_ids_ips_missing", "SR 3.3, SR 6.2", "medium",
            src_zone="port2", dst_zone="CONTROL", _dev="FW-SITE")                           # via interfaces
        add("fw", "config_logging_disabled", "SR 2.8", "medium", _dev="FW-SITE")             # firewall finding
        add("hist", "z_check", "SR 3.3", "low", src_ip="10.50.3.10", dst_ip="52.10.20.30")  # host member by MAC
        add("intra", "z_check", "SR 3.3", "low", src_ip="10.50.20.21", dst_ip="10.50.1.11")  # HMI → PLC, both Control
        add("undoc", "z_check", "SR 3.3", "low", src_ip="10.50.3.10", dst_ip="10.50.1.11")   # historian → PLC
        add("half", "z_check", "SR 3.3", "low", src_ip="10.50.3.20", dst_ip="10.50.1.11")    # no-zone host → PLC
        s.commit()
    return sid, ids


def test_device_findings_judged_against_zone_sl_t(tmp_path):
    with _api(tmp_path / "judge.db") as c:
        sid, ids = _judge_seed(c)
        with c.Session() as s:
            before = sorted((f.id, f.check_name, f.severity, f.status, f.title) for f in s.query(Finding))
        rows = {f["title"]: f for f in c.get("/findings", params={"site_id": sid, "limit": 500}).json()}
        j = {k: rows[k]["zone_judgement"] for k in ids}
        assert (j["plc-sl1"]["zones"], j["plc-sl1"]["zone_sl_t"], j["plc-sl1"]["verdict"]) == (["Control"], 2, "applies")
        assert j["plc-sl3"]["verdict"] == "beyond" and j["plc-sl3"]["check_sl"] == 3
        assert (j["pair"]["via"], j["pair"]["conduit"], j["pair"]["zone_sl_t"], j["pair"]["verdict"]) == \
            ("conduit", "Supervisory", 4, "applies")
        assert j["dmz"]["verdict"] == "no_sl_t"
        # option 2: documentation status of a two-ended finding
        assert j["plc-sl1"]["documentation"] is None                      # one end only
        assert j["pair"]["documentation"] == "documented"                  # Ops ↔ Control: conduit Supervisory
        assert j["policy"]["documentation"] == "documented"
        assert j["hist"]["documentation"] == "external"                    # historian → the Internet
        assert j["egress"]["documentation"] == "external"
        assert j["intra"]["documentation"] == "intra_zone"
        assert j["undoc"]["documentation"] == "undocumented"               # Enterprise ↔ Control: no conduit
        assert j["half"]["documentation"] == "partial"                     # Control ↔ host in no zone
        assert j["nozone"] is None
        assert (j["hist"]["zones"], j["hist"]["zone_sl_t"]) == (["Enterprise"], 1)    # MAC member, address-only evidence
        assert j["egress"]["verdict"] == "applies" and "Internet" in j["egress"]["note"]   # SL3 check, SL-T 2: owner rule
        assert (j["policy"]["via"], j["policy"]["conduit"]) == ("conduit", "Supervisory")
        # a firewall finding: the highest target of the documented conduits FW-SITE carries (policy 12)
        assert (j["fw"]["via"], j["fw"]["firewall"], j["fw"]["zones"], j["fw"]["zone_sl_t"]) == \
            ("firewall", "FW-SITE", ["Supervisory"], 4)
        # severities are untouched
        assert rows["plc-sl3"]["severity"] == "medium" and rows["egress"]["severity"] == "critical"

        def scope(v):
            r = c.get("/findings", params={"site_id": sid, "zone_scope": v, "limit": 500})
            assert r.status_code == 200, r.text
            return sorted(f["title"] for f in r.json() if f["title"] in ids), int(r.headers["X-Total-Count"])
        assert scope("beyond")[0] == ["plc-sl3"]
        assert scope("no_sl_t")[0] == ["dmz"]
        assert scope("no_zone")[0] == ["nozone"]
        assert {"plc-sl1", "pair", "egress", "policy", "fw", "hist", "intra", "undoc", "half"} == set(scope("applies")[0])

        def doc(v):
            r = c.get("/findings", params={"site_id": sid, "conduit_doc": v, "limit": 500})
            assert r.status_code == 200, r.text
            return sorted(f["title"] for f in r.json() if f["title"] in ids)
        assert doc("undocumented") == ["undoc"] and doc("intra_zone") == ["intra"]
        assert doc("documented") == ["pair", "policy"] and doc("partial") == ["half"]
        assert c.get("/findings", params={"site_id": sid, "conduit_doc": "x"}).status_code == 422
        assert c.get("/findings", params={"site_id": sid, "zone_scope": "bogus"}).status_code == 422

        csv_rows = {r["title"]: r for r in _rows(c.get("/findings/export", params={"site_id": sid}))}
        assert (csv_rows["plc-sl3"]["iec_zone"], csv_rows["plc-sl3"]["zone_sl_t"], csv_rows["plc-sl3"]["zone_verdict"]) == \
            ("Control", "2", "beyond")
        assert csv_rows["pair"]["iec_zone"] == "Supervisory" and csv_rows["nozone"]["iec_zone"] == ""
        assert csv_rows["undoc"]["zone_documentation"] == "undocumented" and csv_rows["intra"]["zone_documentation"] == "intra zone"
        assert [r["title"] for r in _rows(c.get("/findings/export", params={"site_id": sid, "conduit_doc": "undocumented"}))] == ["undoc"]
        only = _rows(c.get("/findings/export", params={"site_id": sid, "zone_scope": "beyond"}))
        assert [r["title"] for r in only] == ["plc-sl3"]
        with c.Session() as s:
            after = sorted((f.id, f.check_name, f.severity, f.status, f.title) for f in s.query(Finding))
        assert after == before


def test_report_zone_section_and_judgement(tmp_path):
    import generate_report as gr
    with _api(tmp_path / "rep.db") as c:
        sid, ids = _judge_seed(c)
        c.patch(f"/iec-zones/{c.get('/iec-zones', params={'site_id': sid}).json()['zones'][0]['id']}",
                params={"site_id": sid}, json={"sl_a": 1, "sl_a_note": "assessment"})
        with c.Session() as s:
            on = gr.collect_report_data(s, site_id=sid)
            off = gr.collect_report_data(s, site_id=sid, include_zones=False)
            plain = lambda d: sorted((f["id"], f["check_name"], f["severity"], f["status"]) for f in d["findings"])
            assert plain(on) == plain(off) and on["sev_status"] == off["sev_status"]
            assert off["zones"] is None and all("zone" not in f for f in off["findings"])
            z = on["zones"]
            assert {x["name"] for x in z["zones"]} == {"Control", "Ops", "DMZ", "Enterprise"}
            by = {f["title"]: f.get("zone") for f in on["findings"]}
            assert by["plc-sl3"]["verdict"] == "beyond" and by["nozone"] is None
            ctl = next(t for t in z["tally"] if t["scope"] == "Control")
            assert ctl["beyond"] == 1 and sum(ctl["applies"].values()) >= 1
            assert any(x["sl_a"] == 1 and x["sl_a_status"] == "below" for x in z["zones"])
            story = gr.build_zones(on)
            text = " ".join(getattr(f, "text", "") for f in story if hasattr(f, "text"))
            assert "Zones and Conduits (IEC 62443)" in text and gr.build_zones(off) == []
            pdf = gr.generate_report_bytes(s, site_id=sid)
            assert pdf[:4] == b"%PDF"
        r = c.get("/reports/compliance.pdf", params={"site_id": sid, "include_zones": "false"})
        assert r.status_code == 200 and r.content[:4] == b"%PDF"


def test_report_without_zones_has_no_section(tmp_path):
    import generate_report as gr
    with _api(tmp_path / "nz.db") as c:
        sid = _seed(c)
        with c.Session() as s:
            d = gr.collect_report_data(s, site_id=sid)
        assert d["zones"] is None and gr.build_zones(d) == []


# ------------------------------------------------- undocumented_conduit --
def _open(c, sid, check="undocumented_conduit"):
    return {f["title"]: f for f in c.get("/findings", params={"site_id": sid, "check_name": check, "status": "open",
                                                              "limit": 500}).json()}


def test_undocumented_conduit_check(tmp_path):
    """Option 4: a zone pair with a permitting policy or traffic and no documented
    conduit is a finding; documenting the conduit (or removing the path)
    closes it; pairs with assets in no zone or the Internet are not findings."""
    with _api(tmp_path / "uc.db") as c:
        sid = _seed(c)
        P = {"site_id": sid}
        # no zones: nothing
        assert c.post("/reviews/run", params=P).status_code == 200
        assert _open(c, sid) == {}
        ctl = c.post("/iec-zones", params=P, json={"name": "Control", "sl_t": 2}).json()["zone"]["id"]
        ops = c.post("/iec-zones", params=P, json={"name": "Ops", "sl_t": 3}).json()["zone"]["id"]
        ent = c.post("/iec-zones", params=P, json={"name": "Enterprise", "sl_t": 1}).json()["zone"]["id"]
        c.post(f"/iec-zones/{ctl}/members", params=P, json={"kind": "fw_zone", "ref": "FW-SITE/CONTROL"})
        c.post(f"/iec-zones/{ops}/members", params=P, json={"kind": "interface", "ref": "FW-SITE/port2"})
        c.post(f"/iec-zones/{ent}/members", params=P, json={"kind": "interface", "ref": "FW-SITE/port3"})
        assert c.post("/reviews/run", params=P).status_code == 200
        got = _open(c, sid)
        names = {frozenset((f["detail"]["zone_a"], f["detail"]["zone_b"])) for f in got.values()}
        assert names == {frozenset(("Control", "Ops")), frozenset(("Enterprise", "Ops"))}, names
        co = next(f for f in got.values() if f["detail"]["zone_a"] == "Control")
        assert co["severity"] == "high" and co["detail"]["sessions"] >= 1 and co["detail"]["policies"] >= 1
        assert co["checklist_id"] == "1.4" and "no documented conduit" in co["title"]
        eo = next(f for f in got.values() if "Enterprise" in (f["detail"]["zone_a"], f["detail"]["zone_b"]))
        assert eo["severity"] == "medium"                          # traffic seen, no control assets
        # the DMZ jump box (port4, in no zone) → Control and the Internet pairs are not findings
        assert all("not in a zone" not in f["title"] and "Internet" not in f["title"] for f in got.values())
        # the explanation knows the check
        r = c.get(f"/findings/{co['id']}/explanation", params=P)
        assert r.status_code == 200 and "conduit" in r.text.lower()
        # documenting the conduit closes it on the next run; the other stays
        c.post("/iec-conduits", params=P, json={"zone_a_id": ctl, "zone_b_id": ops, "name": "Supervisory", "sl_t": 3})
        assert c.post("/reviews/run", params=P).status_code == 200
        got = _open(c, sid)
        assert [f["detail"]["zone_b"] for f in got.values()] == ["Enterprise"]
        with c.Session() as s:
            closed = [f for f in s.query(Finding).filter(Finding.check_name == "undocumented_conduit",
                                                         Finding.status == "closed")]
        assert len(closed) == 1 and "Auto-resolved" in (closed[0].notes or "")
        # re-running does not duplicate the open one
        assert c.post("/reviews/run", params=P).status_code == 200
        assert len(_open(c, sid)) == 1
        # removing the conduit raises it again
        cid = c.get("/iec-conduits", params=P).json()["conduits"][0]["id"]
        c.delete(f"/iec-conduits/{cid}", params=P)
        assert c.post("/reviews/run", params=P).status_code == 200
        assert len(_open(c, sid)) == 2


# ---------------------------------------- option 3: service-aware lowering --
def test_conduit_services_lower_covered_findings(tmp_path):
    """A finding on a documented conduit is shown one step lower only when the
    conduit's services cover its service and its sources (when set) cover
    its source; never OT egress; recorded severity and counts unchanged;
    reverts when the conduit changes."""
    import generate_report as gr
    with _api(tmp_path / "opt3.db") as c:
        sid, ids = _judge_seed(c)
        P = {"site_id": sid}
        cond = c.get("/iec-conduits", params=P).json()["conduits"][0]            # Supervisory: Control ↔ Ops
        with c.Session() as s:
            def add(key, check, sr, sev, **detail):
                f = Finding(site_id=sid, category="periodic_review", check_name=check, severity=sev, status="open",
                            isa62443_sr=sr, title=key, detail=detail, source_ref=key)
                s.add(f)
                s.flush()
                ids[key] = f.id
            add("ews-s7", "session_it_ot_bypass", "SR 5.1 RE2", "critical", src_ip="10.50.2.20", dst_ip="10.50.1.11",
                dst_port=102, transport="tcp")                                   # EWS → PLC S7 over the conduit
            add("scada-telnet", "cleartext_credentials", "SR 1.5", "high", src_ip="10.50.2.10", dst_ip="10.50.1.11",
                dst_port=23, transport="tcp")                                    # Telnet: not in the services
            add("noport", "ot_it_dependency", "SR 5.1 RE2", "medium", src_ip="10.50.2.20", dst_ip="10.50.1.11")
            add("egress2", "session_ot_internet_egress", "SR 5.1 RE2", "critical", src_ip="10.50.1.11",
                dst_ip="8.8.8.8", dst_port=102, transport="tcp")                 # never lowered
            s.commit()

        def rows():
            return {f["title"]: f for f in c.get("/findings", params={**P, "limit": 500}).json()}
        # no services: nothing lowered
        r = rows()
        assert all(f["shown_severity"] == f["severity"] and not f["severity_adjustment"] for f in r.values())
        # bad tokens are refused
        assert c.patch(f"/iec-conduits/{cond['id']}", params=P, json={"services": "s7comm, bogus"}).status_code == 422
        assert c.patch(f"/iec-conduits/{cond['id']}", params=P, json={"sources": "10.50.2.20, nope"}).status_code == 422
        # services cover S7 and RDP
        r2 = c.patch(f"/iec-conduits/{cond['id']}", params=P, json={"services": "s7comm, rdp"})
        assert r2.status_code == 200 and r2.json()["conduit"]["services"] == "s7comm, rdp"
        r = rows()
        assert (r["ews-s7"]["severity"], r["ews-s7"]["shown_severity"]) == ("critical", "high")
        assert "Supervisory" in r["ews-s7"]["severity_adjustment"] and "tcp/102" in r["ews-s7"]["severity_adjustment"]
        assert r["scada-telnet"]["shown_severity"] == "high" and not r["scada-telnet"]["severity_adjustment"]
        assert r["noport"]["shown_severity"] == "medium" and not r["noport"]["severity_adjustment"]
        assert r["pair"]["shown_severity"] == "low" and not r["pair"]["severity_adjustment"]      # no port in evidence
        # 'any' covers a finding without a port, but never OT egress
        c.patch(f"/iec-conduits/{cond['id']}", params=P, json={"services": "any"})
        r = rows()
        assert r["noport"]["shown_severity"] == "low" and r["scada-telnet"]["shown_severity"] == "medium"
        assert r["egress2"]["shown_severity"] == "critical" and not r["egress2"]["severity_adjustment"]
        # sources restrict it to the EWS
        c.patch(f"/iec-conduits/{cond['id']}", params=P, json={"services": "s7comm, telnet", "sources": "10.50.2.20"})
        r = rows()
        assert r["ews-s7"]["shown_severity"] == "high" and "from 10.50.2.20" in r["ews-s7"]["severity_adjustment"]
        assert r["scada-telnet"]["shown_severity"] == "high" and not r["scada-telnet"]["severity_adjustment"]
        # stored severities, summary counts and sort are untouched
        with c.Session() as s:
            assert s.query(Finding).filter(Finding.id == ids["ews-s7"]).one().severity == "critical"
        summ = c.get("/findings/summary", params=P).json()
        assert summ["by_severity"].get("critical", 0) >= 2
        # CSV
        csv_rows = {x["title"]: x for x in _rows(c.get("/findings/export", params=P))}
        assert (csv_rows["ews-s7"]["severity"], csv_rows["ews-s7"]["shown_severity"]) == ("critical", "high")
        assert "Supervisory" in csv_rows["ews-s7"]["severity_adjustment"] and csv_rows["scada-telnet"]["severity_adjustment"] == ""
        cr = [x for x in _rows(c.get("/iec-zones/export", params={**P, "table": "conduits"})) if x["documented"] == "yes"]
        assert cr and cr[0]["conduit_services"] == "s7comm, telnet" and cr[0]["conduit_sources"] == "10.50.2.20/32"
        # PDF: the row shows the lowered severity, the recorded one stays in the data
        with c.Session() as s:
            data = gr.collect_report_data(s, site_id=sid)
            f = next(x for x in data["findings"] if x["title"] == "ews-s7")
            assert f["severity"] == "critical" and f["zone"]["adjustment"]
            assert gr._sev_cell_shown(f).text.startswith("<font") and "HIGH" in gr._sev_cell_shown(f).text
            assert gr.generate_report_bytes(s, site_id=sid)[:4] == b"%PDF"
        # clearing the services reverts everything
        c.patch(f"/iec-conduits/{cond['id']}", params=P, json={"services": None, "sources": None})
        r = rows()
        assert r["ews-s7"]["shown_severity"] == "critical" and not r["ews-s7"]["severity_adjustment"]


# -------------------------------------------- assets in several zones --
def test_assets_in_several_zones_are_findings(tmp_path):
    """Owner (2026-10-11): a host or network in two zones is never refused; it
    is reported (host_in_multiple_zones / network_in_multiple_zones), high when
    the zones' SL-T differ, and closes when the asset is back in one zone."""
    with _api(tmp_path / "mz.db") as c:
        sid = _seed(c)
        P = {"site_id": sid}
        a = c.post("/iec-zones", params=P, json={"name": "A", "sl_t": 2}).json()["zone"]["id"]
        b = c.post("/iec-zones", params=P, json={"name": "B", "sl_t": 3}).json()["zone"]["id"]
        c2 = c.post("/iec-zones", params=P, json={"name": "C", "sl_t": 2}).json()["zone"]["id"]
        # the same subnet in A and B (different SL-T), the same host in A and C (same SL-T)
        for zid in (a, b):
            assert c.post(f"/iec-zones/{zid}/members", params=P, json={"kind": "subnet", "ref": "10.50.2.0/24"}).status_code == 200
        for zid in (a, c2):
            assert c.post(f"/iec-zones/{zid}/members", params=P, json={"kind": "host", "ref": "00:00:00:00:01:0b"}).status_code == 200
        d = c.get("/iec-zones", params=P).json()
        assert [o["network"] for o in d["overlaps"]] == ["10.50.2.0/24"]
        assert [m["addresses"] for m in d["multi_zone_hosts"]] == [["10.50.1.11"]]
        assert c.post("/reviews/run", params=P).status_code == 200
        got = {f["check_name"]: f for f in c.get("/findings", params={**P, "status": "open", "limit": 500}).json()
               if f["check_name"] in ("host_in_multiple_zones", "network_in_multiple_zones")}
        assert got["network_in_multiple_zones"]["severity"] == "high"       # SL-T 2 vs 3
        assert got["network_in_multiple_zones"]["detail"]["network"] == "10.50.2.0/24"
        assert got["host_in_multiple_zones"]["severity"] == "medium" and got["host_in_multiple_zones"]["detail"]["zones"] == ["A", "C"]
        assert got["host_in_multiple_zones"]["checklist_id"] == "1.2"
        r = c.get(f"/findings/{got['host_in_multiple_zones']['id']}/explanation", params=P)
        assert r.status_code == 200 and "exactly one" in r.text
        # re-run: no duplicates
        assert c.post("/reviews/run", params=P).status_code == 200
        assert len([f for f in c.get("/findings", params={**P, "status": "open", "limit": 500}).json()
                    if f["check_name"] in ("host_in_multiple_zones", "network_in_multiple_zones")]) == 2
        # fix both: remove the subnet from B, move the host into C
        mb = next(m for z in d["zones"] if z["name"] == "B" for m in z["members"])
        assert c.delete(f"/iec-zones/members/{mb['id']}", params=P).status_code in (200, 204)
        assert c.post(f"/iec-zones/{c2}/members", params=P, json={"kind": "host", "ref": "00:00:00:00:01:0b", "move": True}).status_code == 200
        assert c.post("/reviews/run", params=P).status_code == 200
        assert not [f for f in c.get("/findings", params={**P, "status": "open", "limit": 500}).json()
                    if f["check_name"] in ("host_in_multiple_zones", "network_in_multiple_zones")]
