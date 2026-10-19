"""IO-01 .. IO-13: an isolated OT network seen only through a capture -
one broadcast domain carrying several subnets, unmanaged switches, no router,
no Internet.  A small synthetic capture is built inline (no tabletop data)."""
import random
import sys
from pathlib import Path

import pytest
from scapy.all import ARP, BOOTP, DHCP, IP, TCP, UDP, Ether, Raw, wrpcap

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "sample_data"))
from generate_sample_pcap import modbus_frame, s7comm_read_var_frame  # noqa: E402

import app.parsers.alert_engine as ae  # noqa: E402
from app.parsers.profinet_analyzer import parse_profinet  # noqa: E402
from tests.test_cov_routes import _api  # noqa: E402

T0 = 1791450000.0
M = {"PLC": "00:1b:1b:c1:00:10", "IO": "00:a0:45:c1:00:20", "HMI": "00:d0:c9:c0:00:10",
     "HIST": "00:14:22:c0:00:20", "EWS": "00:1b:78:c0:00:30", "VFD": "00:80:f4:0a:00:11",
     "LAPTOP": "8c:16:45:c1:02:00", "AP": "50:c7:bf:c0:02:54", "PHONE": "a4:83:e7:c0:01:01"}
IP4 = {"PLC": "192.168.1.10", "IO": "192.168.1.20", "HMI": "192.168.0.10", "HIST": "192.168.0.20",
       "EWS": "192.168.0.30", "VFD": "10.10.10.11", "LAPTOP": "192.168.1.200", "AP": "192.168.0.254",
       "PHONE": "192.168.0.101"}
HMI_EXTRA = ["192.168.1.250", "10.10.10.250"]


def _build(path: Path, span: float = 600.0) -> Path:
    random.seed(7)
    pk = []

    def put(p, ts):
        p.time = ts
        pk.append(p)

    def arp_claim(name, ip, ts):        # gratuitous ARP: the MAC claims the address
        put(Ether(src=M[name], dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=M[name], psrc=ip, pdst=ip), ts)

    def tcp(sm, sip, dm, dip, dport, reqs, ts):
        sport = random.randint(49152, 65000)
        s, a, t = 1000, 9000, [ts]

        def P(x, y, xm, ym, sp, dp, fl, load=b"", sq=0, ak=0):
            p = Ether(src=xm, dst=ym) / IP(src=x, dst=y) / TCP(sport=sp, dport=dp, flags=fl, seq=sq, ack=ak)
            put(p / Raw(load=load) if load else p, t[0])
            t[0] += 0.002
        P(sip, dip, sm, dm, sport, dport, "S", sq=s)
        P(dip, sip, dm, sm, dport, sport, "SA", sq=a, ak=s + 1); s += 1; a += 1
        P(sip, dip, sm, dm, sport, dport, "A", sq=s, ak=a)
        for req, resp in reqs:
            P(sip, dip, sm, dm, sport, dport, "PA", req, sq=s, ak=a); s += len(req)
            P(dip, sip, dm, sm, dport, sport, "PA", resp, sq=a, ak=s); a += len(resp)
        P(sip, dip, sm, dm, sport, dport, "FA", sq=s, ak=a)
        P(dip, sip, dm, sm, dport, sport, "FA", sq=a, ak=s + 1)

    t = T0
    for n in ("PLC", "IO", "HMI", "HIST", "VFD", "AP", "EWS", "LAPTOP"):
        arp_claim(n, IP4[n], t); t += 0.5             # EWS appears only here (IO-10)
    for ip in HMI_EXTRA:
        arp_claim("HMI", ip, t); t += 0.5
    arp_claim("LAPTOP", "10.10.10.200", t)
    s7 = s7comm_read_var_frame()
    mb_r = modbus_frame(1, 1, 3, (0).to_bytes(2, "big") + (4).to_bytes(2, "big"))
    mb_rr = modbus_frame(1, 1, 3, bytes([8]) + bytes(8))
    step = span / 10
    for i in range(10):
        ts = T0 + 5 + i * step
        # HMI polls the PLC from its controller-subnet address and the drive
        # from its drive-subnet address: one MAC, three subnets (IO-01 / IO-02)
        tcp(M["HMI"], "192.168.1.250", M["PLC"], IP4["PLC"], 102, [(s7, s7)], ts)
        tcp(M["HMI"], "10.10.10.250", M["VFD"], IP4["VFD"], 502, [(mb_r, mb_rr)], ts + 1)
        tcp(M["HIST"], IP4["HIST"], M["HMI"], IP4["HMI"], 445, [(b"\x00\x00\x00\x04abcd", b"\x00\x00\x00\x04efgh")],
            ts + 2)
        # dead gateway: two hosts keep asking for 192.168.0.1 (IO-08)
        for n in ("HMI", "HIST"):
            put(Ether(src=M[n], dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=M[n], psrc=IP4[n], pdst="192.168.0.1"),
                ts + 3)
        # phone behind the consumer AP tries public DNS / HTTPS, no answer (IO-07)
        put(Ether(src=M["PHONE"], dst=M["AP"]) / IP(src=IP4["PHONE"], dst="8.8.8.8")
            / UDP(sport=53000 + i, dport=53) / Raw(load=b"\x12\x34\x01\x00" + bytes(8)), ts + 4)
        put(Ether(src=M["PHONE"], dst=M["AP"]) / IP(src=IP4["PHONE"], dst="17.253.144.10")
            / TCP(sport=50000 + i, dport=443, flags="S"), ts + 4.5)
        # syslog is one-way and stays a session
        put(Ether(src=M["PLC"], dst=M["HIST"]) / IP(src=IP4["PLC"], dst=IP4["HIST"])
            / UDP(sport=514, dport=514) / Raw(load=b"<14>plc ok"), ts + 5)
    # the AP hands out a lease (IO-04)
    ph = M["PHONE"]
    ch = bytes.fromhex(ph.replace(":", "")) + bytes(10)
    for mt in ("offer", "ack"):
        put(Ether(src=M["AP"], dst="ff:ff:ff:ff:ff:ff") / IP(src=IP4["AP"], dst="255.255.255.255")
            / UDP(sport=67, dport=68) / BOOTP(op=2, yiaddr=IP4["PHONE"], siaddr=IP4["AP"], chaddr=ch, xid=9)
            / DHCP(options=[("message-type", mt), ("server_id", IP4["AP"]), ("router", IP4["AP"]), "end"]),
            T0 + 2 + (mt == "ack") * 0.1)
    # the laptop re-addresses the IO device over PROFINET DCP (IO-06)
    block = bytes([1, 2]) + (14).to_bytes(2, "big") + (1).to_bytes(2, "big") + bytes([192, 168, 1, 21, 255, 255,
                                                                                         255, 0, 0, 0, 0, 0])
    dcp = ((0xFEFD).to_bytes(2, "big") + bytes([4, 0]) + (0x1234).to_bytes(4, "big") + bytes(2)
           + len(block).to_bytes(2, "big") + block)
    put(Ether(src=M["LAPTOP"], dst=M["IO"], type=0x8892) / Raw(load=dcp), T0 + 50)
    pk.sort(key=lambda p: p.time)
    wrpcap(str(path), pk)
    return path


@pytest.fixture(scope="module")
def run(tmp_path_factory):
    tmp_path = tmp_path_factory.mktemp("io")
    mp = pytest.MonkeyPatch()
    mp.setattr(ae, "_NTP_MIN_CAPTURE_SECONDS", 300)
    cm = _api(tmp_path / "io.db")
    c = cm.__enter__()
    pcap = _build(tmp_path / "io.pcap")
    r = c.post("/ingest/pcap", files={"file": ("io.pcap", pcap.read_bytes(), "application/octet-stream")})
    assert r.status_code == 200, r.text[:500]
    up = r.json()
    assert c.post("/reviews/run").status_code == 200
    f = c.get("/findings", params={"status": "open", "limit": 5000}).json()
    f = f if isinstance(f, list) else f.get("findings") or f.get("items")
    h = c.get("/hosts", params={"limit": 5000}).json()
    h = h if isinstance(h, list) else h.get("hosts") or h.get("items")
    yield c, up, f, h
    cm.__exit__(None, None, None)
    mp.undo()


def _by(findings, check):
    return [x for x in findings if x["check_name"] == check]


def test_dcp_set_is_a_write():                                           # IO-06
    block = bytes([2, 2]) + (6).to_bytes(2, "big") + bytes(2) + b"io-01x"
    p = (0xFEFD).to_bytes(2, "big") + bytes([4, 0]) + bytes(4) + bytes(2) + len(block).to_bytes(2, "big") + block
    r = parse_profinet(p)
    assert (r["operation"], r["summary"]) == ("write", "dcp_set_name_of_station")
    reset = bytes([5, 6]) + (2).to_bytes(2, "big") + bytes(2)
    p = (0xFEFD).to_bytes(2, "big") + bytes([4, 0]) + bytes(4) + bytes(2) + len(reset).to_bytes(2, "big") + reset
    assert parse_profinet(p)["operation"] == "control"
    ident = (0xFEFE).to_bytes(2, "big") + bytes([5, 0]) + bytes(4) + bytes(2) + (4).to_bytes(2, "big") + bytes(
        [0xFF, 0xFF, 0, 0])
    assert parse_profinet(ident)["operation"] == "discovery"


def test_isolated_capture(run):
    c, up, f, hosts = run
    seg = up["stats"]["capture_segment"]
    # IO-01: the multi-homed HMI is not a gateway; IO-03: one layer-2 domain
    assert M["HMI"] not in seg["gateway_macs"]
    assert seg["domains"] == [sorted(["10.10.10.0/24", "192.168.0.0/24", "192.168.1.0/24"])]
    hmi = [h for h in hosts if h["ip"] == IP4["HMI"]][0]
    assert hmi["device_type"] != "router"
    # IO-05: the consumer AP forwarded the phone's traffic but is not trusted
    ap = [h for h in hosts if h["ip"] == IP4["AP"]][0]
    assert ap.get("classification_source") != "capture_gateway"
    # IO-10: EWS only ever claimed its address in ARP and is a host
    assert IP4["EWS"] in {h["ip"] for h in hosts}

    # IO-02
    mh = {x["detail"]["mac"]: x for x in _by(f, "multi_homed_host")}
    assert M["HMI"] in mh and mh[M["HMI"]]["severity"] == "high"
    assert set(mh[M["HMI"]]["detail"]["addresses"]) == {IP4["HMI"], *HMI_EXTRA}
    # IO-03
    flat = _by(f, "flat_control_segment")
    assert flat and all("one layer-2 segment" in x["title"] for x in flat)
    # IO-04
    dh = _by(f, "rogue_dhcp_server")
    assert len(dh) == 1 and dh[0]["detail"].get("ip") == IP4["AP"]
    wl = _by(f, "wireless_in_ot_zone")
    assert [x["detail"]["mac"] for x in wl] == [M["AP"]] and wl[0]["detail"]["dhcp_server"]
    ud = {x["detail"]["mac"]: x for x in _by(f, "unknown_device")}
    assert M["PHONE"] in ud and ud[M["PHONE"]]["detail"]["consumer_device"]
    assert ud[M["PHONE"]]["severity"] == "high"                # it tried the Internet
    # IO-07: unanswered requests are attempts, not sessions
    eg = _by(f, "session_ot_internet_egress")
    assert eg and all(x["detail"].get("attempt") for x in eg)
    assert {x["detail"]["dst_ip"] for x in eg} == {"8.8.8.8", "17.253.144.10"}
    assert all("tried to reach" in x["title"] for x in eg)
    # IO-08
    dg = _by(f, "dead_default_gateway")
    assert [x["detail"]["ip"] for x in dg] == ["192.168.0.1"]
    # IO-09
    assert any(x["detail"].get("rule_key") == "ntp_none" or "No time synchronisation" in x["title"]
               for x in _by(f, "ntp_sync"))
    # IO-06: the DCP Set is an unauthorised write
    w = _by(f, "unauthorized_industrial_write")
    assert any("profinet" in x["title"] for x in w)
    # IO-11: the upload note reports evidence, never "Likely"
    notes = " ".join(up.get("upload_notes") or [])
    assert "Likely" not in notes
    assert any(f"{ip} (unidentified, not in any inventory)" in notes
               for ip in (IP4["LAPTOP"], "10.10.10.200"))
    # IO-12: the laptop is one unknown-device finding for its two addresses
    if M["LAPTOP"] in ud:
        assert set(ud[M["LAPTOP"]]["detail"]["addresses"]) >= {IP4["LAPTOP"]}
    assert len([x for x in _by(f, "unknown_device") if x["detail"]["mac"] == M["LAPTOP"]]) <= 1
    # IO-13: SMB between OT hosts on one segment is no IT dependency
    assert not [x for x in _by(f, "ot_it_dependency") if x["detail"].get("dst_ip") == IP4["HMI"]]


def test_one_way_udp_stays_a_session(run):                               # IO-07
    c, up, f, hosts = run
    att = up["stats"]["connection_attempts"]
    assert att.get("unanswered", 0) >= 1
    assert up["stats"]["sessions"] >= 3      # syslog and the TCP polls stay sessions


def test_multi_homed_same_level_is_medium(db_session=None):
    """Two subnets that hold no L0-L1 devices and the same levels: medium."""
    from sqlalchemy import create_engine
    from sqlalchemy.orm import sessionmaker
    from sqlalchemy.pool import StaticPool
    from app.models import Base, Host
    from app.parsers import segments
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    Base.metadata.create_all(eng)
    db = sessionmaker(bind=eng)()
    mac = "00:1b:78:00:00:01"
    db.add_all([Host(ip="10.3.0.5", mac=mac, purdue_level=3), Host(ip="10.4.0.5", mac=mac, purdue_level=3),
                Host(ip="10.3.0.6", mac="00:1b:78:00:00:02", purdue_level=3),
                Host(ip="10.4.0.6", mac="00:1b:78:00:00:03", purdue_level=3)])
    db.flush()
    out = segments.review_multi_homed_hosts(db)
    assert [(x.detail["mac"], x.severity) for x in out] == [(mac, "medium")]
    db.close()


def test_topology_and_classify_control(run):
    """Lanes and the Classify control on capture-only data."""
    c, up, f, hosts = run
    t = c.get("/topology").json()
    by = {n["ip"]: n for n in t["nodes"]}
    seg = "10.10.10.0/24 + 192.168.0.0/24 + 192.168.1.0/24"
    assert by[IP4["HMI"]]["segment"] == seg and by[IP4["PLC"]]["segment"] == seg
    # RS-02: Internet addresses the phone tried and that never answered are
    # attempts, not hosts
    assert "8.8.8.8" not in by and "17.253.144.10" not in by and by[IP4["HMI"]]["external"] is False
    assert by[IP4["PLC"]]["device_label"] == "Programmable Logic Controller"
    assert "SMB" in {e["protocol_label"] for e in t["edges"]}
    # suggestions
    hmi = by[IP4["HMI"]]["id"]
    s = c.get(f"/hosts/{hmi}/classification-suggestion").json()
    assert {x["ip"] for x in s["same_mac"]} == set(HMI_EXTRA)
    assert s["suggestions"][0]["device_type"] == "hmi" and s["suggestions"][0]["purdue_level"] == 2
    ap = c.get(f"/hosts/{by[IP4['AP']]['id']}/classification-suggestion").json()
    assert ap["suggestions"][0]["device_type"] == "router" and ap["evidence"]["dhcp_server"]
    plc = c.get(f"/hosts/{by[IP4['PLC']]['id']}/classification-suggestion").json()
    assert plc["suggestions"][0]["device_type"] == "plc"
    # one save covers every address of the MAC, and is undone the same way
    r = c.patch(f"/hosts/{hmi}/classification",
                params={"device_type": "hmi", "apply_to_same_mac": "true"}).json()
    assert len(r["updated_ids"]) == 3
    lv = {n["ip"]: (n["device_type"], n["purdue_level"]) for n in c.get("/topology").json()["nodes"]}
    assert all(lv[ip] == ("hmi", 2) for ip in [IP4["HMI"], *HMI_EXTRA])
    d = c.delete(f"/hosts/{hmi}/classification", params={"apply_to_same_mac": "true"}).json()
    assert len(d["cleared"]) == 3
