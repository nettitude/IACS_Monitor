"""SF-5 (blocked attempts into other zones, unidentified hosts reaching across
the firewall) and SF-6 (one policy serving several conduits; per-interface
labels; per-pair zone judgement)."""
from datetime import datetime, timezone

from app.models import ConnectionAttempt, Finding, FirewallRule, Host, NetworkSession
from tests.test_cov_routes import _api
from tests.test_iec_zones import _seed

NOW = datetime.now(timezone.utc)


def _open(c, sid, *checks):
    return [f for f in c.get("/findings", params={"site_id": sid, "status": "open", "limit": 1000}).json()
            if f["check_name"] in checks]


def _zones(c, sid, conduit=True):
    P = {"site_id": sid}
    ids = {}
    for name, sl, kind, ref in (("Control", 2, "fw_zone", "FW-SITE/CONTROL"), ("Ops", 3, "interface", "FW-SITE/port2"),
                                ("Enterprise", 2, "subnet", "10.50.3.0/24")):
        ids[name] = c.post("/iec-zones", params=P, json={"name": name, "sl_t": sl}).json()["zone"]["id"]
        assert c.post(f"/iec-zones/{ids[name]}/members", params=P, json={"kind": kind, "ref": ref}).status_code == 200
    return ids


# ---------------------------------------------------------------- SF-6 --
def _multi_rule(c, sid):
    with c.Session() as s:
        s.add(FirewallRule(site_id=sid, firewall_id=1, device_name="FW-SITE", device_type="fortigate", policy_id="20",
                           vdom="root", src_zone="port2,port3", dst_zone="port1", src="all", dst="10.50.1.11/32",
                           protocol="tcp", dst_port="502", action="accept", enabled=True))
        s.commit()


def test_policy_spanning_two_conduits(tmp_path):
    with _api(tmp_path / "sf6.db") as c:
        sid = _seed(c)
        P = {"site_id": sid}
        _multi_rule(c, sid)
        assert c.post("/reviews/run", params=P).status_code == 200
        assert _open(c, sid, "policy_spans_multiple_conduits") == []            # no zones: nothing to span
        ids = _zones(c, sid)
        assert c.post("/reviews/run", params=P).status_code == 200
        got = _open(c, sid, "policy_spans_multiple_conduits")
        p20 = [f for f in got if f["detail"]["policy_id"] == "20"]
        assert len(p20) == 1, [f["title"] for f in got]
        f = p20[0]
        assert {tuple(sorted(r["zones"])) for r in f["detail"]["conduits"]} == {("Control", "Ops"), ("Control", "Enterprise")}
        assert f["severity"] == "medium" and f["checklist_id"] == "3.1"            # Control holds L1 assets
        assert "split" in c.get(f"/findings/{f['id']}/explanation", params=P).text.lower()
        # single-pair policies are not findings (policy 5: port3 -> port2 only)
        assert not [x for x in got if x["detail"]["policy_id"] == "5"]
        # SF-6 labels: per interface, ordered by level, never "'port2,port3' (L..)"
        bypass = [x for x in c.get("/findings", params={**P, "limit": 1000}).json()
                  if x["check_name"] == "rule_it_ot_bypass" and x["detail"].get("policy_id") == "20"]
        assert bypass and "port2 (L3) + port3 (L4)" in bypass[0]["title"] and "port2,port3" not in bypass[0]["title"]
        assert [p["name"] for p in bypass[0]["detail"]["src_zone_parts"]] == ["port2", "port3"]
        # the judgement treats the policy as two conduits: undocumented, strictest target
        j = bypass[0]["zone_judgement"]
        assert j["via"] == "conduits" and j["documentation"] == "undocumented" and j["zone_sl_t"] == 3
        assert {tuple(sorted(p["zones"])) for p in j["pairs"]} == {("Control", "Ops"), ("Control", "Enterprise")}
        # documenting both conduits: documented, conduit names listed
        c.post("/iec-conduits", params=P, json={"zone_a_id": ids["Control"], "zone_b_id": ids["Ops"], "name": "Sup"})
        c.post("/iec-conduits", params=P, json={"zone_a_id": ids["Control"], "zone_b_id": ids["Enterprise"], "name": "Hist"})
        x = next(x for x in c.get("/findings", params={**P, "limit": 1000}).json() if x["id"] == bypass[0]["id"])
        assert x["zone_judgement"]["documentation"] == "documented" and set(x["zone_judgement"]["conduit"].split(", ")) == {"Sup", "Hist"}
        # splitting the policy closes the finding
        with c.Session() as s:
            for r in s.query(FirewallRule).filter(FirewallRule.policy_id == "20"):
                r.src_zone = "port2"
            s.commit()
        assert c.post("/reviews/run", params=P).status_code == 200
        assert not [x for x in _open(c, sid, "policy_spans_multiple_conduits") if x["detail"]["policy_id"] == "20"]


def test_access_path_zone_parts_label():
    from app.parsers.access_path_findings import path_label
    from app.parsers.access_paths import zone_parts
    parts = zone_parts({(1, "port1"): 1.0, (1, "port2"): 3.0}, 1, "port2,port1")
    assert [p["name"] for p in parts] == ["port1", "port2"]
    row = {"src": {"level": 1, "zone": "port2,port1", "scope": "any", "zone_parts": parts},
           "dst": {"level": 4, "zone": "port3", "scope": "10.50.3.5"}}
    assert path_label(row) == "L1 port1 (L1) + port2 (L3) any → L4 port3 10.50.3.5"
    assert zone_parts({}, 1, "any") is None and zone_parts({}, 1, "port1") is None


# ---------------------------------------------------------------- SF-5 --
def _rogue(c, sid, with_session=False):
    with c.Session() as s:
        h = Host(ip="10.50.1.200", mac="3c:52:82:01:02:00", site_id=sid, first_seen=NOW, last_seen=NOW,
                 sources=["pcap"], purdue_level=1, classification_source="interface_label", vendor="Hewlett Packard")
        s.add(h)
        s.flush()

        def att(dst, port, outcome="unanswered", n=2, tr="tcp"):
            s.add(ConnectionAttempt(site_id=sid, src_ip="10.50.1.200", src_mac=h.mac, dst_ip=dst, dst_port=port,
                                    transport=tr, outcome=outcome, count=n, first_seen=NOW, last_seen=NOW))
        att("10.50.2.10", 3389)                      # Ops, RDP
        att("10.50.2.10", 22)                        # Ops, SSH
        att("10.50.3.10", 445, "refused")            # Enterprise, SMB
        att("10.50.1.11", 502)                       # same zone: not cross-zone
        att("142.250.72.14", 443, n=5)               # Internet: the egress checks'
        att("10.50.2.1", 443)                        # the firewall itself: local-in
        if with_session:                             # the same flow also got through
            dst = s.query(Host).filter(Host.ip == "10.50.2.20").one()
            s.add(NetworkSession(src_host_id=h.id, dst_host_id=dst.id, src_port=40000, dst_port=80,
                                 transport="tcp", packet_count=4, protocol="http", last_seen=NOW))
            att("10.50.2.20", 80)
        s.commit()


def test_blocked_attempts_without_and_with_zones(tmp_path):
    with _api(tmp_path / "sf5.db") as c:
        sid = _seed(c)
        P = {"site_id": sid}
        _rogue(c, sid, with_session=True)
        # without zones: firewall interface networks are the segments
        assert c.post("/reviews/run", params=P).status_code == 200
        b = _open(c, sid, "blocked_cross_zone_attempts")
        assert len(b) == 1 and b[0]["detail"]["ip"] == "10.50.1.200"
        tg = {(t["dst_ip"], t["port"]) for t in b[0]["detail"]["targets"]}
        assert tg == {("10.50.2.10", 3389), ("10.50.2.10", 22), ("10.50.3.10", 445)}, tg
        assert b[0]["severity"] == "high" and b[0]["detail"]["unknown_source"] and b[0]["detail"]["management_ports"]
        assert b[0]["checklist_id"] == "8.8"
        # unknown_device: unidentified host on L1 reaching across the firewall (no inventory loaded)
        u = [f for f in _open(c, sid, "unknown_device") if f["detail"].get("ip") == "10.50.1.200"]
        assert len(u) == 1 and "across the firewall" in u[0]["title"] and u[0]["severity"] == "high"
        assert {x["ip"] for x in u[0]["detail"]["across_firewall"]} >= {"10.50.2.10", "10.50.3.10"}
        # with zones and a conduit: RDP from the rogue is listed on the conduit -> designed traffic dropped
        ids = _zones(c, sid)
        c.post("/iec-conduits", params=P, json={"zone_a_id": ids["Control"], "zone_b_id": ids["Ops"], "name": "Sup",
                                                "services": "rdp", "sources": "10.50.1.200"})
        assert c.post("/reviews/run", params=P).status_code == 200
        b = _open(c, sid, "blocked_cross_zone_attempts")
        st = {(t["dst_ip"], t["port"]): t["status"] for t in b[0]["detail"]["targets"]}
        assert st == {("10.50.2.10", 22): "outside_services", ("10.50.3.10", 445): "undocumented"}, st
        assert b[0]["detail"]["src_zone"] == "Control"
        cb = _open(c, sid, "conduit_service_blocked")
        assert len(cb) == 1 and cb[0]["severity"] == "info" and cb[0]["detail"]["targets"][0]["port"] == 3389
        # classifying and approving the host: no longer unknown -> medium (management ports)
        with c.Session() as s:
            h = s.query(Host).filter(Host.ip == "10.50.1.200").one()
            h.device_type, h.classification_source, h.approved = "engineering_workstation", "manual", True
            s.commit()
        assert c.post("/reviews/run", params=P).status_code == 200
        b = _open(c, sid, "blocked_cross_zone_attempts")
        assert b[0]["severity"] == "medium" and not b[0]["detail"]["unknown_source"]
        assert not [f for f in _open(c, sid, "unknown_device") if f["detail"].get("ip") == "10.50.1.200"]
        # the attempts gone (capture removed) -> both close
        with c.Session() as s:
            s.query(ConnectionAttempt).delete()
            s.commit()
        assert c.post("/reviews/run", params=P).status_code == 200
        assert not _open(c, sid, "blocked_cross_zone_attempts", "conduit_service_blocked")
