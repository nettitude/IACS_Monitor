"""RS G4: level-based bypass wording and severity, engineering workstation
access (RS-08), OT never directly on the Internet, sweep escalation (RS-09)
and grouped SNMP community findings (RS-10)."""
from types import SimpleNamespace

from scapy.all import IP, UDP, Dot1Q, Ether, Raw, rdpcap, wrpcap

from app.parsers.alert_engine import _bypass_wording, _engineering_session
from app.parsers.traffic_findings import _write_wording
from tests.test_cov_routes import _api
from tests.test_rs_span import CORE, H, T0, _capture

SNMP_GET = bytes.fromhex("302902010104067075626c6963a01c020401020304020100020100300e300c06082b060102010101000500")
SNMP_RESP = bytes.fromhex("302902010104067075626c6963a21c020401020304020100020100300e300c06082b060102010101000500")


def test_bypass_wording_by_level():
    w = _bypass_wording(3, 1)
    assert w["title"] == "Level-skipping session" and "IT" not in w["title"]
    assert w["skips"] == "skips L2 (site operations straight to basic control)"
    assert _bypass_wording(4, 1)["title"] == "Direct IT-to-OT session"
    assert "skips L3.5 and L3 and L2" in _bypass_wording(4, 1)["skips"]
    assert _bypass_wording(3.5, 1)["title"] == "DMZ host straight to controllers"
    assert _bypass_wording(5, 2)["src_name"] == "internet host"


def test_engineering_session_needs_a_classified_ews_at_l3_or_below():
    ews = SimpleNamespace(device_type="engineering_workstation", purdue_level=3)
    plc = SimpleNamespace(device_type="plc", purdue_level=1)
    assert _engineering_session(ews, plc) == (ews, plc) and _engineering_session(plc, ews) == (ews, plc)
    it_ews = SimpleNamespace(device_type="engineering_workstation", purdue_level=4)
    assert _engineering_session(it_ews, plc) is None
    ops = SimpleNamespace(device_type="operations_workstation", purdue_level=3)
    assert _engineering_session(ops, plc) is None


def test_write_wording():
    ev = {"protocol": "s7comm", "operation": "program", "summary": "request_download", "src_ip": "10.0.0.5",
          "dst_ip": "10.0.1.10", "occurrences": 1}
    sev, title, extra = _write_wording(ev, SimpleNamespace(device_type="engineering_workstation", purdue_level=3))
    assert sev == "high" and title.startswith("Engineering access to approve: s7comm request_download")
    assert extra["engineering_ws"] is True
    sev, title, _ = _write_wording(ev, None)
    assert sev == "critical" and title.startswith("Unauthorized s7comm request_download (program) from 10.0.0.5")


def _with_snmp(tmp_path):
    """The SPAN capture plus host B polling three addresses with SNMP v2c 'public'."""
    pk = list(rdpcap(_capture(tmp_path)))
    B = H["B"]
    for i, dip in enumerate(("10.40.30.10", "10.40.30.11", "10.40.30.1")):
        t = T0 + 300 + i
        dmac = {"10.40.30.10": H["P"][1], "10.40.30.11": H["Q"][1]}.get(dip, CORE)
        q = IP(src=B[0], dst=dip, id=7000 + i) / UDP(sport=50161, dport=161) / Raw(SNMP_GET)
        r = IP(src=dip, dst=B[0], id=7100 + i) / UDP(sport=161, dport=50161) / Raw(SNMP_RESP)
        for p, dt in ((Ether(src=B[1], dst=CORE) / Dot1Q(vlan=10) / q, 0),
                      (Ether(src=CORE, dst=dmac) / Dot1Q(vlan=30) / q.copy(), .0003),
                      (Ether(src=dmac, dst=CORE) / Dot1Q(vlan=30) / r, .01),
                      (Ether(src=CORE, dst=B[1]) / Dot1Q(vlan=10) / r.copy(), .0103)):
            p.time = t + dt
            pk.append(p)
    pk.sort(key=lambda p: p.time)
    path = tmp_path / "g4.pcap"
    wrpcap(str(path), pk)
    return path


def _open(c, check):
    f = c.get("/findings", params={"status": "open", "limit": 5000}).json()
    f = f if isinstance(f, list) else f.get("findings") or f.get("items")
    return [x for x in f if x["check_name"] == check]


def _hid(c, ip):
    hs = c.get("/hosts", params={"limit": 5000}).json()
    hs = hs if isinstance(hs, list) else hs.get("hosts") or hs.get("items")
    return next(h["id"] for h in hs if h["ip"] == ip)


def test_g4_on_a_routed_capture(tmp_path):
    with _api(tmp_path / "g4.db") as c:
        pc = _with_snmp(tmp_path)
        assert c.post("/ingest/pcap", files={"file": ("g.pcap", pc.read_bytes(),
                                                      "application/octet-stream")}).status_code == 200
        A, B, P = H["A"][0], H["B"][0], H["P"][0]
        assert c.patch(f"/hosts/{_hid(c, P)}/classification", params={"device_type": "plc"}).status_code == 200
        # B-20: findings of a host talking to an unclassified one are held from auto-resolve
        assert c.patch(f"/hosts/{_hid(c, B)}/classification",
                       params={"device_type": "historian"}).status_code == 200

        # RS-10: one SNMP finding for the poller, the targets listed
        assert c.post("/reviews/run").status_code == 200
        snmp = [x for x in _open(c, "cleartext_credentials") if "SNMP" in x["title"]]
        assert len(snmp) == 1 and snmp[0]["detail"]["target_count"] == 3
        assert snmp[0]["detail"]["grouped"] and f"from {B} to 3 devices" in snmp[0]["title"]
        assert snmp[0]["severity"] == "critical"                       # the PLC got the community

        # RS-08: an operations workstation (L3) polling the PLC - worded by level, high
        assert c.patch(f"/hosts/{_hid(c, A)}/classification",
                       params={"device_type": "historian"}).status_code == 200
        assert c.post("/reviews/run").status_code == 200
        byp = [x for x in _open(c, "session_it_ot_bypass") if x["detail"]["it_host_ip"] == A]
        assert byp and all(x["title"].startswith("Level-skipping session (observed traffic)") for x in byp)
        assert all("skips L2" in x["title"] and x["severity"] == "high" for x in byp)
        assert not _open(c, "engineering_access_unapproved")

        # the same host as an engineering workstation: engineering access to approve, no bypass
        assert c.patch(f"/hosts/{_hid(c, A)}/classification",
                       params={"device_type": "engineering_workstation"}).status_code == 200
        assert c.post("/reviews/run").status_code == 200
        assert not [x for x in _open(c, "session_it_ot_bypass") if x["detail"]["it_host_ip"] == A]
        eng = _open(c, "engineering_access_unapproved")
        assert len(eng) == 1 and eng[0]["severity"] == "medium"
        assert eng[0]["title"].startswith(f"Engineering access to approve: engineering workstation {A} (L3) → {P}")
        exp = c.get(f"/findings/{eng[0]['id']}/explanation")
        assert exp.status_code == 200

        # approved as an engineering source: nothing left
        r = c.post("/management/networks", json={"kind": "host", "cidr": A, "role": "engineering_ws"})
        assert r.status_code in (200, 201)
        assert c.post("/reviews/run").status_code == 200
        assert not _open(c, "engineering_access_unapproved")
        assert not [x for x in _open(c, "session_it_ot_bypass") if x["detail"]["it_host_ip"] == A]

        # RS-09: B (L3) swept telnet on the PLC VLAN - below its level, management port -> high
        sw = [x for x in _open(c, "session_scanning_anomaly") if x["title"].startswith("Host sweep")]
        assert sw and sw[0]["severity"] == "high"
        assert any("telnet (23)" in r_ for r_ in sw[0]["detail"]["escalation"])
        # B as an IP camera at L4 probing L1: the level reason leads the title
        assert c.patch(f"/hosts/{_hid(c, B)}/classification",
                       params={"device_type": "ip_camera", "purdue_level": "4"}).status_code == 200
        assert c.post("/reviews/run").status_code == 200
        sw = [x for x in _open(c, "session_scanning_anomaly") if x["title"].startswith("Host sweep")]
        reasons = sw[0]["detail"]["escalation"]
        assert reasons[0].startswith("the source (L4) probed L1 devices")
        assert any("ip camera equipment" in r_ for r_ in reasons)


def test_ews_internet_access_is_high(tmp_path):
    from tests.test_rs_span import _span_with_internet
    with _api(tmp_path / "e.db") as c:
        pc = _span_with_internet(tmp_path)
        c.post("/ingest/pcap", files={"file": ("r.pcap", pc.read_bytes(), "application/octet-stream")})
        A = H["A"][0]
        assert c.patch(f"/hosts/{_hid(c, A)}/classification",
                       params={"device_type": "engineering_workstation"}).status_code == 200
        assert c.post("/reviews/run").status_code == 200
        eg = [x for x in _open(c, "session_ot_internet_egress") if x["detail"].get("src_ip") == A]
        assert eg and all(x["severity"] == "high" and "engineering workstation" in x["title"] for x in eg)
