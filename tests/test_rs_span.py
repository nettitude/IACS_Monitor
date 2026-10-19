"""RS group 1: a SPAN of a layer-3 switch - 802.1Q VLANs (RS-07), no false
"one layer-2 segment" from the two copies of a routed packet (RS-01), each
routed packet counted once (RS-11), and no host for an address that never
answered (RS-02)."""
import pytest
from scapy.all import ARP, IP, TCP, UDP, Dot1Q, Ether, Raw, wrpcap
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import Base, Host, NetworkSession
from app.parsers.pcap_parser import ingest_pcap

T0 = 1_791_540_000.0
CORE = "00:1b:54:aa:00:01"
H = {"A": ("10.40.10.10", "f8:bc:12:10:00:10", 10), "B": ("10.40.10.11", "f8:bc:12:10:00:11", 10),
     "P": ("10.40.30.10", "00:1b:1b:30:00:10", 30), "Q": ("10.40.30.11", "00:1b:1b:30:00:11", 30)}
GW = {10: "10.40.10.1", 30: "10.40.30.1"}


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


def _capture(tmp_path, sweep=True):
    pk = []

    def put(p, t):
        p.time = t
        pk.append(p)

    def routed(src, dst, l4, t, ipid):
        (sip, smac, sv), (dip, dmac, dv) = H[src], H[dst]
        l3 = IP(src=sip, dst=dip, id=ipid) / l4
        put(Ether(src=smac, dst=CORE) / Dot1Q(vlan=sv) / l3.copy(), t)
        l3b = l3.copy()
        l3b.ttl -= 1
        put(Ether(src=CORE, dst=dmac) / Dot1Q(vlan=dv) / l3b, t + 0.0003)

    t = T0
    for n, (ip, mac, v) in H.items():
        put(Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / Dot1Q(vlan=v) / ARP(op=1, hwsrc=mac, psrc=ip, pdst=GW[v]), t)
        put(Ether(src=CORE, dst=mac) / Dot1Q(vlan=v) / ARP(op=2, hwsrc=CORE, psrc=GW[v], hwdst=mac, pdst=ip), t + .001)
        t += 0.1
    ipid = 100
    for i in range(5):                 # A polls P across the router: 7 packets per connection
        t = T0 + 10 + i * 10
        sp = 50000 + i
        seq = [("A", "P", "S", b""), ("P", "A", "SA", b""), ("A", "P", "A", b""), ("A", "P", "PA", b"req!"),
               ("P", "A", "PA", b"resp"), ("A", "P", "FA", b""), ("P", "A", "FA", b"")]
        for k, (s, d, fl, load) in enumerate(seq):
            ipid += 1
            fwd = s == "A"
            l4 = TCP(sport=sp if fwd else 502, dport=502 if fwd else sp, flags=fl, seq=1000 + k)
            routed(s, d, l4 / Raw(load=load) if load else l4, t + k * 0.01, ipid)
        # same-VLAN conversation A <-> B (switched, one copy)
        for k, (s, d, fl) in enumerate([("A", "B", "S"), ("B", "A", "SA"), ("A", "B", "A"), ("A", "B", "FA"),
                                        ("B", "A", "FA")]):
            (sip, smac, v), (dip, dmac, _) = H[s], H[d]
            fwd = s == "A"
            put(Ether(src=smac, dst=dmac) / Dot1Q(vlan=v) / IP(src=sip, dst=dip, id=5000 + i * 10 + k)
                / TCP(sport=40000 + i if fwd else 445, dport=445 if fwd else 40000 + i, flags=fl)
                / Raw(load=b"smb"), t + 5 + k * 0.01)
    if sweep:                          # B sweeps the PLC VLAN: only P and Q exist
        t = T0 + 100
        for host in range(2, 40):
            dip = f"10.40.30.{host}"
            put(Ether(src=H["B"][1], dst=CORE) / Dot1Q(vlan=10) / IP(src=H["B"][0], dst=dip, id=9000 + host)
                / TCP(sport=41000 + host, dport=23, flags="S"), t + host * 0.05)
    pk.sort(key=lambda p: p.time)
    path = tmp_path / "span.pcap"
    wrpcap(str(path), pk)
    return str(path)


def test_span_of_a_routing_switch(db, tmp_path):
    stats = ingest_pcap(_capture(tmp_path), db)
    seg = stats["capture_segment"]
    # RS-07: the VLAN of each subnet / host comes from the 802.1Q tags
    assert seg["vlans"] == {"10.40.10.0/24": [10], "10.40.30.0/24": [30]}
    vl = {h.ip: (h.vlan, h.vlan_source) for h in db.query(Host)}
    assert vl["10.40.10.10"] == ("10", "pcap_8021q") and vl["10.40.30.10"] == ("30", "pcap_8021q")
    # RS-01: two VLANs behind a router are two segments
    assert seg["domains"] == [["10.40.10.0/24"], ["10.40.30.0/24"]]
    # RS-11: the routed copy is not counted again (7 packets per connection)
    rows = (db.query(NetworkSession).join(Host, NetworkSession.dst_host_id == Host.id)
            .filter(Host.ip == "10.40.30.10", NetworkSession.dst_port == 502).all())
    assert [r.packet_count for r in rows] == [7] * 5 and stats["span_duplicates"] == 35
    # RS-02: swept addresses that never answered are attempts, not hosts
    ips = {h.ip for h in db.query(Host)}
    assert not any(ip.startswith("10.40.30.") and ip not in ("10.40.30.1", "10.40.30.10", "10.40.30.11")
                   for ip in ips if ip)
    assert stats["connection_attempts"]["unanswered"] >= 36
    assert stats["silent_addresses_not_hosts"] >= 36


def test_untagged_flat_capture_still_one_segment(db, tmp_path):
    """IO-03 keeps working: two subnets on one wire, a frame goes MAC to MAC."""
    a, b = ("192.168.1.10", "00:1b:1b:01:00:10"), ("192.168.0.20", "00:1b:1b:00:00:20")
    pk = []
    for i, (s, d) in enumerate([(a, b), (b, a)] * 3):
        p = Ether(src=s[1], dst=d[1]) / IP(src=s[0], dst=d[0]) / TCP(sport=40000, dport=102, flags="PA") / Raw(b"x")
        p.time = T0 + i
        pk.append(p)
    for ip, mac in (a, b, ("192.168.1.11", "00:1b:1b:01:00:11"), ("192.168.0.21", "00:1b:1b:00:00:21")):
        p = Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / ARP(op=1, hwsrc=mac, psrc=ip, pdst=ip)
        p.time = T0 + 10
        pk.append(p)
    path = tmp_path / "flat.pcap"
    wrpcap(str(path), pk)
    stats = ingest_pcap(str(path), db)
    assert stats["capture_segment"]["domains"] == [["192.168.0.0/24", "192.168.1.0/24"]]
    assert "vlans" not in stats["capture_segment"]


# ------------------------------------------------------------------ group 2 --
def test_external_level_and_implicit_route_direction(db):
    from app.parsers.l3_switch import external_level_fn
    from app.parsers.reachability import _Context
    f = external_level_fn(db)
    assert f("8.8.8.8", None) == 5 and f("10.1.1.1", None) is None and f("8.8.8.8", 2) == 2

    class R:
        policy_id = "implicit:route:CORE"
    assert _Context.direction_unverified(object(), None, R()) is False


_SW = """hostname CORE-SW01
ip routing
vlan 10
 name WORKSTATIONS
vlan 30
 name PLC
vlan 250
 name FW-TRANSIT
interface Vlan10
 ip address 10.40.10.1 255.255.255.0
interface Vlan30
 ip address 10.40.30.1 255.255.255.0
interface Vlan250
 ip address 10.40.250.2 255.255.255.252
ip route 0.0.0.0 0.0.0.0 10.40.250.1
end
"""
_FW = """config system global
    set hostname FW-INET
end
config system interface
    edit "internal"
        set ip 10.40.250.1 255.255.255.252
        set type physical
    next
    edit "wan1"
        set ip 203.0.113.2 255.255.255.252
        set type physical
    next
end
config firewall address
    edit "OT-ALL"
        set subnet 10.40.0.0 255.255.0.0
    next
end
config firewall policy
    edit 1
        set name "OT-to-Internet"
        set srcintf "internal"
        set dstintf "wan1"
        set srcaddr "OT-ALL"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "ALL"
        set nat enable
    next
end
"""
FWMAC = "00:09:0f:bb:00:01"


def _span_with_internet(tmp_path):
    pk = []
    ipid = [1]

    def put(p, t):
        p.time = t
        pk.append(p)

    def send(sip, smac, sv, dip, dmac, dv, l4, t, ext=None):
        ipid[0] += 1
        l3 = IP(src=sip, dst=dip, id=ipid[0]) / l4
        if ext == "out":      # host -> core (its VLAN), core -> FW (250)
            put(Ether(src=smac, dst=CORE) / Dot1Q(vlan=sv) / l3.copy(), t)
            put(Ether(src=CORE, dst=FWMAC) / Dot1Q(vlan=250) / l3.copy(), t + .0003)
        elif ext == "in":     # FW -> core (250), core -> host
            put(Ether(src=FWMAC, dst=CORE) / Dot1Q(vlan=250) / l3.copy(), t)
            put(Ether(src=CORE, dst=dmac) / Dot1Q(vlan=dv) / l3.copy(), t + .0003)
        else:
            put(Ether(src=smac, dst=CORE) / Dot1Q(vlan=sv) / l3.copy(), t)
            put(Ether(src=CORE, dst=dmac) / Dot1Q(vlan=dv) / l3.copy(), t + .0003)

    A, P = H["A"], H["P"]
    for n, (ip, mac, v) in H.items():
        put(Ether(src=mac, dst="ff:ff:ff:ff:ff:ff") / Dot1Q(vlan=v) / ARP(op=1, hwsrc=mac, psrc=ip, pdst=GW[v]), T0)
        put(Ether(src=CORE, dst=mac) / Dot1Q(vlan=v) / ARP(op=2, hwsrc=CORE, psrc=GW[v], hwdst=mac, pdst=ip), T0 + .01)
    s7 = bytes([3, 0, 0, 0x19, 2, 0xF0, 0x80, 0x32, 1, 0, 0, 0, 1, 0, 8, 0, 0, 4, 1, 0x12, 4, 0x11, 0x84, 0, 0])
    for i in range(6):
        t = T0 + 5 + i * 30
        sp = 50000 + i
        for k, (fwd, fl, load) in enumerate([(1, "S", b""), (0, "SA", b""), (1, "A", b""), (1, "PA", s7),
                                              (0, "PA", s7), (1, "FA", b""), (0, "FA", b"")]):
            src, dst = (A, P) if fwd else (P, A)
            l4 = TCP(sport=sp if fwd else 102, dport=102 if fwd else sp, flags=fl, seq=1000 + k)
            send(src[0], src[1], src[2], dst[0], dst[1], dst[2], l4 / Raw(load=load) if load else l4, t + k * .01)
        send(P[0], P[1], 30, "162.159.200.1", None, None, UDP(sport=123, dport=123) / Raw(b"\x23" + bytes(47)),
             t + 1, ext="out")
        send("162.159.200.1", None, None, P[0], P[1], 30, UDP(sport=123, dport=123) / Raw(b"\x24" + bytes(47)),
             t + 1.02, ext="in")
        for k, (fwd, fl, load) in enumerate([(1, "S", b""), (0, "SA", b""), (1, "PA", b"\x16\x03\x01" + bytes(40)),
                                              (0, "PA", b"\x16\x03\x03" + bytes(40)), (1, "FA", b""), (0, "FA", b"")]):
            l4 = TCP(sport=60000 + i if fwd else 443, dport=443 if fwd else 60000 + i, flags=fl, seq=2000 + k)
            l4 = l4 / Raw(load=load) if load else l4
            if fwd:
                send(A[0], A[1], 10, "142.250.72.14", None, None, l4, t + 2 + k * .01, ext="out")
            else:
                send("142.250.72.14", None, None, A[0], A[1], 10, l4, t + 2 + k * .01, ext="in")
    pk.sort(key=lambda p: p.time)
    path = tmp_path / "routed.pcap"
    wrpcap(str(path), pk)
    return path


def test_switch_then_firewall(tmp_path):
    """RS-03 / RS-04 / RS-12 on a routed capture with the switch and firewall configs."""
    from tests.test_cov_routes import _api
    with _api(tmp_path / "g2.db") as c:
        pc = _span_with_internet(tmp_path)
        assert c.post("/ingest/pcap", files={"file": ("r.pcap", pc.read_bytes(), "application/octet-stream")}).status_code == 200
        assert c.post("/ingest/switch", params={"device_name": "CORE-SW01"},
                      files={"file": ("sw.txt", _SW.encode(), "text/plain")}).status_code == 200
        assert c.post("/ingest/fortigate-config", params={"firewall_name": "FW-INET"},
                      files={"file": ("fw.txt", _FW.encode(), "text/plain")}).status_code == 200
        assert c.post("/reviews/run").status_code == 200

        def findings():
            f = c.get("/findings", params={"status": "open", "limit": 5000}).json()
            return f if isinstance(f, list) else f.get("findings") or f.get("items")
        f = findings()
        # RS-03: the firewall policy carried the Internet traffic - not unused
        assert not [x for x in f if x["check_name"] == "unused_policy"]
        # RS-12: the workstation VLAN is routed to the PLC VLAN by the switch
        eg = [x for x in f if x["check_name"] == "session_ot_internet_egress" and "10.40.10.10" in x["title"]]
        assert eg and "routed to 10.40.30.0/24 by CORE-SW01" in eg[0]["title"] and eg[0]["severity"] == "medium"
        # label the levels, then RS-04: L1 egress through switch + firewall is critical
        lv = {"Vlan10": 3, "Vlan30": 1, "Vlan250": 3, "internal": 3, "wan1": 5}
        for fw in c.get("/topology/state").json()["firewalls"]:
            for i in fw["interfaces"]:
                if i["name"] in lv:
                    assert c.post("/topology/set-interface-side",
                                  json={"interface_id": i["id"], "purdue_level": lv[i["name"]],
                                        "side": "outside" if i["name"] == "wan1" else "inside"}).status_code == 200
        assert c.post("/reviews/run").status_code == 200
        f = findings()
        pe = {x["title"].split(":")[0]: x for x in f if x["check_name"] == "path_ot_internet_egress"}
        assert "Internet egress from L1" in pe and pe["Internet egress from L1"]["severity"] == "critical"
        assert "[seen in capture]" in pe["Internet egress from L1"]["title"]
        assert not [x for x in f if x["check_name"] == "unused_policy"]
        # no duplicate upward-skip findings for switch-only or Internet chains
        assert not [x for x in f if x["check_name"] == "chain_ot_upward_skip"
                    and ("L5" in x["title"] or "across 1 firewall" in x["title"])]
