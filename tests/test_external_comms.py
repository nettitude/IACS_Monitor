"""RS G5: the external communications view - names from the capture (DNS
answers, TLS SNI, HTTP Host), GET /external-comms, POST /external-comms/review,
DELETE /external-comms/review/{review_id} and the effect of a review on the
Internet-egress findings."""
from scapy.all import IP, TCP, UDP, Dot1Q, Ether, Raw, rdpcap, wrpcap

from app.parsers import name_sniff as ns
from app.parsers.external_comms import category_of, domain_of
from tests.test_cov_routes import _api
from tests.test_rs_span import CORE, FWMAC, H, T0, _span_with_internet


def _hello(name: str) -> bytes:
    nm = name.encode()
    sni = ((0).to_bytes(2, "big") + (len(nm) + 5).to_bytes(2, "big") + (len(nm) + 3).to_bytes(2, "big")
           + b"\x00" + len(nm).to_bytes(2, "big") + nm)
    body = b"\x03\x03" + bytes(32) + b"\x00" + b"\x00\x02\x13\x01" + b"\x01\x00" + len(sni).to_bytes(2, "big") + sni
    hs = b"\x01" + len(body).to_bytes(3, "big") + body
    return b"\x16\x03\x01" + len(hs).to_bytes(2, "big") + hs


def _qname(n: str) -> bytes:
    return b"".join(bytes([len(x)]) + x.encode() for x in n.split(".")) + b"\x00"


def _dns_resp(qname: str, ip: str) -> bytes:
    return (b"\x12\x34\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + _qname(qname) + b"\x00\x01\x00\x01"
            + b"\xc0\x0c\x00\x01\x00\x01\x00\x00\x01\x2c\x00\x04" + bytes(int(x) for x in ip.split(".")))


# ---------------------------------------------------------------- name sniffing
def test_name_sniff_units():
    assert ns.dns_answers(_dns_resp("WWW.Google.com", "142.250.72.14")) == [("142.250.72.14", "www.google.com")]
    # a query (not a response) and garbage give nothing
    q = b"\x12\x34\x01\x00\x00\x01\x00\x00\x00\x00\x00\x00" + _qname("x.com") + b"\x00\x01\x00\x01"
    assert ns.dns_answers(q) == [] and ns.dns_answers(b"\x00" * 5) == []
    # AAAA answer
    aaaa = (b"\x00\x01\x81\x80\x00\x01\x00\x01\x00\x00\x00\x00" + _qname("v6.example.org") + b"\x00\x1c\x00\x01"
            + b"\xc0\x0c\x00\x1c\x00\x01\x00\x00\x01\x2c\x00\x10" + bytes(15) + b"\x01")
    assert ns.dns_answers(aaaa) == [("::1", "v6.example.org")]
    assert ns.tls_sni(_hello("api.hik-connect.com")) == "api.hik-connect.com"
    assert ns.tls_sni(b"\x16\x03\x01\x00\x40" + bytes(64)) is None
    assert ns.tls_sni(_hello("a.b")[:30]) is None
    assert ns.http_host(b"GET / HTTP/1.1\r\nHost: Updates.Vendor.com:8080\r\n\r\n") == "updates.vendor.com"
    assert ns.http_host(b"\x16\x03\x01") is None


def test_domain_and_category():
    assert domain_of("a3k7xyz-ats.iot.eu-central-1.amazonaws.com") == "amazonaws.com"
    assert domain_of("router7.teamviewer.com") == "teamviewer.com"
    assert category_of("www.google.com", 443) == "web / office"
    assert category_of("router7.teamviewer.com", 5938) == "remote access"
    # a distinctive port wins over a generic hosting name
    assert category_of("x.iot.eu-central-1.amazonaws.com", 8883) == "MQTT"
    assert category_of(None, 123) == "time"
    assert category_of(None, 443) is None


# ---------------------------------------------------------------- API
def _capture(tmp_path):
    """The routed SPAN capture plus: a DNS answer and a TLS session with SNI
    from the workstation to www.google.com, and a nameless PLC flow to
    45.33.100.7:443 (unknown)."""
    base = _span_with_internet(tmp_path)
    pk = list(rdpcap(str(base)))
    A, P = H["A"], H["P"]
    ipid = [9000]

    def out(sip, smac, sv, dip, l4, t):
        ipid[0] += 1
        l3 = IP(src=sip, dst=dip, id=ipid[0]) / l4
        for p, dt in ((Ether(src=smac, dst=CORE) / Dot1Q(vlan=sv) / l3.copy(), 0),
                      (Ether(src=CORE, dst=FWMAC) / Dot1Q(vlan=250) / l3.copy(), .0003)):
            p.time = t + dt
            pk.append(p)

    def back(sip, dip, dmac, dv, l4, t):
        ipid[0] += 1
        l3 = IP(src=sip, dst=dip, id=ipid[0]) / l4
        for p, dt in ((Ether(src=FWMAC, dst=CORE) / Dot1Q(vlan=250) / l3.copy(), 0),
                      (Ether(src=CORE, dst=dmac) / Dot1Q(vlan=dv) / l3.copy(), .0003)):
            p.time = t + dt
            pk.append(p)

    back("8.8.8.8", A[0], A[1], 10, UDP(sport=53, dport=40000) / Raw(_dns_resp("www.google.com", "142.250.72.14")),
         T0 + 3)
    for i, (src, dst, first) in enumerate(((A, "142.250.72.14", _hello("www.google.com")),
                                           (P, "45.33.100.7", b"\x16\x03\x01\x00\x40" + bytes(64)))):
        t, sp = T0 + 200 + i * 5, 61000 + i
        sv = src[2]
        for k, (fwd, fl, load) in enumerate([(1, "S", b""), (0, "SA", b""), (1, "PA", first),
                                              (0, "PA", b"\x16\x03\x03" + bytes(40)), (1, "FA", b""), (0, "FA", b"")]):
            l4 = TCP(sport=sp if fwd else 443, dport=443 if fwd else sp, flags=fl, seq=3000 + k)
            l4 = l4 / Raw(load=load) if load else l4
            if fwd:
                out(src[0], src[1], sv, dst, l4, t + k * .01)
            else:
                back(dst, src[0], src[1], sv, l4, t + k * .01)
    pk.sort(key=lambda p: p.time)
    path = tmp_path / "ext.pcap"
    wrpcap(str(path), pk)
    return path


def _egress(c):
    f = c.get("/findings", params={"status": "open", "limit": 5000}).json()
    f = f if isinstance(f, list) else f.get("findings") or f.get("items")
    return {x["title"]: x for x in f if x["check_name"] == "session_ot_internet_egress"}


def test_external_comms_view_and_reviews(tmp_path):
    with _api(tmp_path / "x.db") as c:
        pc = _capture(tmp_path)
        up = c.post("/ingest/pcap", files={"file": ("x.pcap", pc.read_bytes(), "application/octet-stream")}).json()
        assert up["stats"]["observed_names"] >= 1

        d = c.get("/external-comms").json()
        rows = {(r["inside"]["ip"], r["dest_key"]): r for r in d["flows"]}
        g = rows[("10.40.10.10", "google.com")]
        assert g["names"][0] == "www.google.com" and g["category"] == "web / office"
        assert g["addresses"] == ["142.250.72.14"] and g["answered"] and g["direction"] == "outbound"
        assert rows[("10.40.30.10", "162.159.200.1")]["category"] == "time"
        unk = rows[("10.40.30.10", "45.33.100.7")]
        assert unk["unknown"] and unk["category"] == "unknown"
        assert d["summary"]["unknown"] == 1 and d["summary"]["unreviewed"] == len(d["flows"])
        assert d["organisation_data"] is False
        # unknown rows first
        assert d["flows"][0]["unknown"] or d["flows"][0]["inside"]["purdue_level"] is not None

        # topology: the outside address carries the name the capture showed
        node = next(n for n in c.get("/topology").json()["nodes"] if n["ip"] == "142.250.72.14")
        assert node["external"] and node["name"] == "www.google.com"

        assert c.post("/reviews/run").status_code == 200
        eg = _egress(c)
        assert any("162.159.200.1:123" in t for t in eg)
        assert any("session to google.com (142.250.72.14:443)" in t for t in eg)      # titled by name

        # approve NTP for every host; mark the unknown flow for removal
        r = c.post("/external-comms/review", json={"src": "*", "dest_key": "162.159.200.1", "status": "approved",
                                                   "note": "site NTP conduit", "created_by": "t"})
        assert r.status_code == 200 and r.json()["created"]
        rid = r.json()["review"]["id"]
        r2 = c.post("/external-comms/review", json={"src": "10.40.30.10", "dest_key": "45.33.100.7",
                                                    "status": "remove"})
        assert r2.status_code == 200
        # re-post changes the status, same row
        r3 = c.post("/external-comms/review", json={"src": "10.40.30.10", "dest_key": "45.33.100.7",
                                                    "status": "remove", "note": "unknown - block"})
        assert not r3.json()["created"] and r3.json()["review"]["id"] == r2.json()["review"]["id"]

        d = c.get("/external-comms").json()
        rows = {(r["inside"]["ip"], r["dest_key"]): r for r in d["flows"]}
        assert rows[("10.40.30.10", "162.159.200.1")]["status"] == "approved"
        assert rows[("10.40.30.10", "162.159.200.1")]["review"]["src"] == "*"
        assert rows[("10.40.30.10", "45.33.100.7")]["status"] == "remove"
        assert not rows[("10.40.30.10", "45.33.100.7")]["unknown"]
        assert d["summary"]["approved"] == 1 and d["summary"]["remove"] == 1

        assert c.post("/reviews/run").status_code == 200
        eg = _egress(c)
        # owner (G4): an OT device never gets direct Internet access - the
        # approval is recorded in the title, the finding stays open
        assert rows[("10.40.30.10", "162.159.200.1")]["ot_host"] and d["summary"]["ot_flows"] >= 2
        ntp = [t for t in eg if "162.159.200.1" in t]
        assert ntp and all("approved on External comms, still not allowed" in t for t in ntp)
        rm = [t for t in eg if "45.33.100.7" in t]
        assert rm and all(t.endswith("- marked for removal") for t in rm)

        # deleting the approval drops the note from the title
        assert c.delete(f"/external-comms/review/{rid}").status_code == 200
        assert c.delete(f"/external-comms/review/{rid}").status_code == 404
        assert c.post("/reviews/run").status_code == 200
        ntp = [t for t in _egress(c) if "162.159.200.1:123" in t]
        assert ntp and not any("approved" in t for t in ntp)


def test_external_comms_errors(tmp_path):
    with _api(tmp_path / "e.db") as c:
        assert c.post("/sites", json={"name": "E", "code": "e"}).status_code in (200, 201)
        assert c.get("/external-comms").json()["flows"] == []
        bad = [{"src": "10.0.0.1", "dest_key": "x.com", "status": "maybe"},
               {"src": "not-an-ip", "dest_key": "x.com", "status": "approved"},
               {"src": "*", "dest_key": "  ", "status": "approved"},
               {"src": "*", "status": "approved"}]
        for b in bad:
            assert c.post("/external-comms/review", json=b).status_code == 422, b
        assert c.delete("/external-comms/review/999").status_code == 404


def test_outside_test():
    """Outside = not in a known network and not in an internal range: an
    undescribed RFC 1918 subnet stays inside, a test-net trunk peer is out."""
    import ipaddress
    from unittest import mock
    from app.parsers import external_comms as ec
    with mock.patch.object(ec, "_known_networks", return_value=[ipaddress.ip_network("10.40.10.0/24")]):
        f = ec.external_fn(None)
        assert not f("10.40.10.7") and not f("10.0.3.99") and not f("192.168.5.5") and not f("100.64.1.1")
        assert f("198.51.100.20") and f("8.8.8.8")
        assert not f("224.0.0.251") and not f("169.254.1.1") and not f("nonsense")
    with mock.patch.object(ec, "_known_networks", return_value=[]):
        assert not ec.external_fn(None)("198.51.100.20") and ec.external_fn(None)("8.8.8.8")


def test_organisation_file(tmp_path, monkeypatch):
    """The optional ip2asn file names the owner of an address range."""
    import gzip
    from app.parsers import external_comms as ec
    f = tmp_path / "ip2asn-v4.tsv.gz"
    with gzip.open(f, "wt") as fh:
        fh.write("3.0.0.0\t3.127.255.255\t16509\tUS\tAMAZON-02\n")
        fh.write("10.0.0.0\t10.255.255.255\t0\tNone\tNot routed\n")
    monkeypatch.setenv("IACS_IP2ASN_FILE", "")
    monkeypatch.setenv("IACS_DATA_DIR", str(tmp_path))
    monkeypatch.setattr(ec, "_ORG", {})
    assert ec.organisation_of("3.120.10.44") == "AS16509 AMAZON-02 (US)"
    assert ec.organisation_of("10.1.1.1") is None and ec.organisation_of("8.8.8.8") is None
    assert ec.organisation_of("bad") is None
