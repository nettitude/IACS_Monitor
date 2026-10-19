"""
F-09: host identity across ingests - DHCP renumbering, IP-only host merge,
IP->new-MAC conflicts, address history, staleness, and the routes.
"""
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from scapy.all import Ether, IP, IPv6, TCP, Raw, wrpcap
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.main as main_mod
from app.db import Base, get_db
from app.models import Finding, Host, HostAddressHistory, NetworkSession, ProtocolDetail
from app.parsers.alert_engine import review_ip_conflicts
from app.parsers.arp_parser import ingest_arp_table
from app.parsers.common import get_or_create_host
from app.parsers.host_identity import HostIdentityResolver, mark_stale_hosts, merge_hosts
from app.parsers.mac_table_parser import ingest_mac_table
from app.parsers.pcap_parser import ingest_pcap


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    session = sessionmaker(bind=engine)()
    yield session
    session.close()


HMI_MAC, PLC_MAC, OTHER_MAC = "00:0c:29:00:00:01", "00:1b:1b:00:00:02", "00:0c:29:00:00:03"
PLC_IP = "10.0.1.10"
T0 = 1_700_000_000.0


def _modbus(txid: int) -> bytes:
    return txid.to_bytes(2, "big") + b"\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a"


def _pcap(tmp_path, name, hmi_ip, hmi_mac=HMI_MAC, t=T0, n=2, sport=40000):
    pkts = []
    for i in range(n):
        p = (Ether(src=hmi_mac, dst=PLC_MAC) / IP(src=hmi_ip, dst=PLC_IP)
             / TCP(sport=sport, dport=502, seq=1 + 12 * i, flags="PA") / Raw(_modbus(i)))
        p.time = t + i
        pkts.append(p)
    path = str(tmp_path / name)
    wrpcap(path, pkts)
    return path


def _history(db, host_id):
    return {(r.ip, r.mac, r.source) for r in
            db.query(HostAddressHistory).filter(HostAddressHistory.host_id == host_id)}


# ------------------------------------------------------------ renumbering ---

def test_dhcp_renumbering_across_two_pcap_ingests(db, tmp_path):
    ingest_pcap(_pcap(tmp_path, "a.pcap", "10.0.1.50"), db)
    hmi = db.query(Host).filter(Host.mac == HMI_MAC).one()
    hmi_id = hmi.id

    stats = ingest_pcap(_pcap(tmp_path, "b.pcap", "10.0.1.77", t=T0 + 86400), db)
    assert stats["hosts_renumbered"] == 1
    assert stats["address_changes"] == [
        {"host_id": hmi_id, "mac": HMI_MAC, "old_ip": "10.0.1.50", "new_ip": "10.0.1.77"}]
    rows = db.query(Host).filter(Host.mac == HMI_MAC).all()
    assert [(h.id, h.ip) for h in rows] == [(hmi_id, "10.0.1.77")]
    assert stats["hosts"] == 0
    assert _history(db, hmi_id) == {("10.0.1.50", HMI_MAC, "pcap"), ("10.0.1.77", HMI_MAC, "pcap")}
    # Both ingests' sessions hang off the same Host row.
    assert {s.src_host_id for s in db.query(NetworkSession)} == {hmi_id}
    assert review_ip_conflicts(db) == []


def test_mac_with_two_ips_in_one_capture_is_not_renumbered(db, tmp_path):
    ingest_pcap(_pcap(tmp_path, "a.pcap", "10.0.1.50"), db)
    p1 = _pcap(tmp_path, "b1.pcap", "10.0.1.50")
    p2 = _pcap(tmp_path, "b2.pcap", "10.0.1.51", sport=40001)
    from scapy.all import rdpcap
    both = str(tmp_path / "b.pcap")
    wrpcap(both, list(rdpcap(p1)) + list(rdpcap(p2)))
    stats = ingest_pcap(both, db)
    assert stats["hosts_renumbered"] == 0
    assert sorted(h.ip for h in db.query(Host).filter(Host.mac == HMI_MAC)) == ["10.0.1.50", "10.0.1.51"]


def test_ipv6_address_never_replaces_ipv4(db, tmp_path):
    ingest_pcap(_pcap(tmp_path, "a.pcap", "10.0.1.50"), db)
    p = (Ether(src=HMI_MAC, dst=PLC_MAC) / IPv6(src="2001:db8::50", dst="2001:db8::10")
         / TCP(sport=40000, dport=502, seq=1, flags="PA") / Raw(_modbus(1)))
    p.time = T0 + 10
    path = str(tmp_path / "v6.pcap")
    wrpcap(path, [p])
    stats = ingest_pcap(path, db)
    assert stats["hosts_renumbered"] == 0
    assert sorted(h.ip for h in db.query(Host).filter(Host.mac == HMI_MAC)) == ["10.0.1.50", "2001:db8::50"]


def test_renumber_merges_ip_only_host_without_losing_rows(db, tmp_path):
    ingest_pcap(_pcap(tmp_path, "a.pcap", "10.0.1.50"), db)
    hmi_id = db.query(Host).filter(Host.mac == HMI_MAC).one().id

    # The new address is already known IP-only (firewall config) and has its
    # own traffic + a finding pointing at that traffic.
    ip_only = get_or_create_host(db, "10.0.1.77", None, "config")
    ip_only.hostname = "hmi-02"
    plc = db.query(Host).filter(Host.ip == PLC_IP).one()
    s = NetworkSession(src_host_id=ip_only.id, dst_host_id=plc.id, src_port=40000, dst_port=502,
                       transport="tcp", protocol="modbus", packet_count=3, byte_count=300)
    other = NetworkSession(src_host_id=ip_only.id, dst_host_id=plc.id, src_port=55555,
                           dst_port=502, transport="tcp", protocol="modbus", packet_count=1)
    db.add_all([s, other])
    db.flush()
    db.add(ProtocolDetail(session_id=s.id, protocol="modbus", fields={}))
    db.add(Finding(category="periodic_review", title="x", session_id=s.id))
    db.commit()
    ip_only_id, s_id, other_id = ip_only.id, s.id, other.id
    hmi_session_id = db.query(NetworkSession).filter(NetworkSession.src_host_id == hmi_id).one().id
    details_before = db.query(ProtocolDetail).count()

    stats = ingest_pcap(_pcap(tmp_path, "b.pcap", "10.0.1.77", t=T0 + 86400), db)
    assert stats["hosts_renumbered"] == 1 and stats["hosts_merged"] == 1
    assert db.get(Host, ip_only_id) is None
    hmi = db.get(Host, hmi_id)
    assert hmi.ip == "10.0.1.77" and hmi.hostname == "hmi-02"
    assert set(hmi.sources) >= {"pcap", "config"}
    # 40000->502 from the IP-only host duplicated the HMI's session: folded.
    assert db.get(NetworkSession, s_id) is None
    folded = db.get(NetworkSession, hmi_session_id)
    assert folded.packet_count == 2 + 3 + 2
    assert db.get(NetworkSession, other_id).src_host_id == hmi_id
    assert db.query(ProtocolDetail).count() == details_before + 2
    assert db.query(ProtocolDetail).filter(ProtocolDetail.session_id == s_id).count() == 0
    assert db.query(Finding).one().session_id == hmi_session_id
    assert ("10.0.1.50", HMI_MAC, "pcap") in _history(db, hmi_id)


# ---------------------------------------------------------------- conflicts --

def test_known_ip_with_new_mac_is_recorded_not_overwritten(db, tmp_path):
    ingest_pcap(_pcap(tmp_path, "a.pcap", "10.0.1.50"), db)
    old_id = db.query(Host).filter(Host.mac == HMI_MAC).one().id
    stats = ingest_pcap(_pcap(tmp_path, "b.pcap", "10.0.1.50", hmi_mac=OTHER_MAC,
                              t=T0 + 60), db)
    assert stats["ip_conflicts"] == 1
    assert stats["ip_conflict_events"][0]["existing_macs"] == [HMI_MAC]
    assert stats["hosts_renumbered"] == 0
    rows = db.query(Host).filter(Host.ip == "10.0.1.50").order_by(Host.id).all()
    assert [(h.id, h.mac) for h in rows][0] == (old_id, HMI_MAC)
    assert [h.mac for h in rows] == [HMI_MAC, OTHER_MAC]
    assert ("10.0.1.50", OTHER_MAC, "pcap") in _history(db, rows[1].id)
    findings = review_ip_conflicts(db)
    assert len(findings) == 1 and findings[0].check_name == "ip_conflict"


# ------------------------------------------------------------- ARP / MAC ---

def test_arp_ingest_renumbers_and_records_history(db):
    ingest_arp_table("? (10.0.2.5) at 00:0c:29:aa:bb:01 [ether] on eth0\n"
                     "? (10.0.2.6) at 00:0c:29:aa:bb:02 [ether] on eth0\n", db)
    host_id = db.query(Host).filter(Host.mac == "00:0c:29:aa:bb:01").one().id
    stats = ingest_arp_table("? (10.0.2.99) at 00:0c:29:aa:bb:01 [ether] on eth0\n"
                             "? (10.0.2.6) at 00:0c:29:aa:bb:02 [ether] on eth0\n", db)
    assert stats["hosts_renumbered"] == 1
    assert db.get(Host, host_id).ip == "10.0.2.99"
    assert db.query(Host).count() == 2
    assert _history(db, host_id) == {("10.0.2.5", "00:0c:29:aa:bb:01", "arp"),
                                     ("10.0.2.99", "00:0c:29:aa:bb:01", "arp")}
    row = (db.query(HostAddressHistory)
           .filter(HostAddressHistory.ip == "10.0.2.6").one())
    assert row.observation_count == 2


def test_arp_cisco_dotted_mac_matches_pcap_host(db, tmp_path):
    ingest_pcap(_pcap(tmp_path, "a.pcap", "10.0.1.50"), db)
    ingest_arp_table(
        "Protocol  Address          Age (min)  Hardware Addr   Type   Interface\n"
        "Internet  10.0.1.50              12   000c.2900.0001  ARPA   Vlan10\n", db)
    host = db.query(Host).filter(Host.mac == HMI_MAC).one()
    assert set(host.sources) == {"pcap", "arp"}


def test_mac_table_ingest_records_history_and_unstales(db):
    h = get_or_create_host(db, "10.0.3.5", "00:0c:29:00:00:42", "arp")
    h.stale = True
    db.commit()
    ingest_mac_table("Vlan    Mac Address       Type        Ports\n"
                     "  10    000c.2900.0042    DYNAMIC     Gi1/0/1\n", db)
    db.refresh(h)
    assert h.stale is False and h.vlan == "10"
    assert (None, "00:0c:29:00:00:42", "mac_table") in _history(db, h.id)


def test_resolver_without_observation_context_never_renumbers(db):
    get_or_create_host(db, "10.0.4.1", "00:0c:29:00:00:51", "arp")
    r = HostIdentityResolver(db, "config")
    r.resolve("10.0.4.2", "00:0c:29:00:00:51")
    assert r.stats["hosts_renumbered"] == 0
    assert db.query(Host).filter(Host.mac == "00:0c:29:00:00:51").count() == 2


def test_merge_hosts_moves_history_and_generic_fks(db):
    keep = get_or_create_host(db, "10.0.5.1", "00:0c:29:00:00:61", "pcap")
    drop = get_or_create_host(db, "10.0.5.2", None, "config")
    drop.device_type, drop.purdue_level, drop.classification_source = "plc", 1, "manual"
    keep.device_type, keep.classification_source = "workstation", "oui_hint"
    db.add_all([HostAddressHistory(host_id=keep.id, ip="10.0.5.9", mac=None, source="config",
                                   observation_count=2),
                HostAddressHistory(host_id=drop.id, ip="10.0.5.9", mac=None, source="config",
                                   observation_count=3),
                HostAddressHistory(host_id=drop.id, ip="10.0.5.2", mac=None, source="config")])
    db.flush()
    drop_id = drop.id
    merge_hosts(db, keep, drop)
    assert db.get(Host, drop_id) is None
    assert (keep.device_type, keep.purdue_level, keep.classification_source) == ("plc", 1, "manual")
    hist = {(r.ip, r.source): r.observation_count
            for r in db.query(HostAddressHistory).filter(HostAddressHistory.host_id == keep.id)}
    assert hist == {("10.0.5.9", "config"): 5, ("10.0.5.2", "config"): 1}


# ---------------------------------------------------------------- staleness --

def test_mark_stale_and_reingest_clears(db, tmp_path):
    ingest_pcap(_pcap(tmp_path, "a.pcap", "10.0.1.50"), db)
    now = datetime.fromtimestamp(T0, tz=timezone.utc) + timedelta(days=45)
    res = mark_stale_hosts(db, older_than_days=30, now=now)
    db.commit()
    assert res["marked_stale"] == 2 and res["stale_total"] == 2
    assert all(h.stale for h in db.query(Host))
    # not old enough with a 60-day window -> cleared again
    res = mark_stale_hosts(db, older_than_days=60, now=now)
    assert res["cleared"] == 2 and res["stale_total"] == 0
    mark_stale_hosts(db, older_than_days=30, now=now)
    db.commit()
    # seen again by a later ingest (packet time newer) -> no longer stale
    ingest_pcap(_pcap(tmp_path, "b.pcap", "10.0.1.50", t=T0 + 50 * 86400), db)
    assert not any(h.stale for h in db.query(Host))


def test_any_ingest_touch_clears_stale(db):
    h = get_or_create_host(db, "10.0.6.1", None, "config")
    h.stale = True
    db.commit()
    get_or_create_host(db, "10.0.6.1", None, "firewall_config")
    assert h.stale is False


# ------------------------------------------------------------------- routes --

@pytest.fixture
def client(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'hi.db'}",
                           connect_args={"check_same_thread": False})
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
    with Session() as s:
        old = datetime.now(timezone.utc) - timedelta(days=90)
        a = Host(ip="10.0.7.1", mac="00:0c:29:00:00:71", sources=["pcap"],
                 first_seen=old, last_seen=old)
        b = Host(ip="10.0.7.2", mac="00:0c:29:00:00:72", sources=["arp"])
        s.add_all([a, b])
        s.flush()
        s.add(HostAddressHistory(host_id=a.id, ip="10.0.7.9", mac=a.mac, source="pcap",
                                 first_seen=old, last_seen=old, observation_count=4))
        s.commit()
    with TestClient(main_mod.app) as c:
        c.engine_session = Session
        yield c
    main_mod.app.dependency_overrides.pop(get_db, None)
    engine.dispose()


def test_routes_stale_and_history(client):
    hosts = client.get("/hosts").json()
    assert all(h["stale"] is False for h in hosts)
    r = client.post("/hosts/mark-stale", params={"older_than_days": 30})
    assert r.status_code == 200, r.text
    assert r.json()["marked_stale"] == 1
    by_ip = {h["ip"]: h for h in client.get("/hosts").json()}
    assert by_ip["10.0.7.1"]["stale"] is True and by_ip["10.0.7.2"]["stale"] is False
    assets = {a["ip"]: a for a in client.get("/assets").json()}
    assert assets["10.0.7.1"]["stale"] is True
    # default window is 30 days
    assert client.post("/hosts/mark-stale").json()["older_than_days"] == 30
    assert client.post("/hosts/mark-stale", params={"older_than_days": -1}).status_code == 422

    hid = by_ip["10.0.7.1"]["id"]
    hist = client.get(f"/hosts/{hid}/history").json()
    assert hist["host_id"] == hid and hist["stale"] is True
    assert hist["history"][0]["ip"] == "10.0.7.9" and hist["history"][0]["observation_count"] == 4
    assert client.get("/hosts/999999/history").status_code == 404


def test_route_arp_upload_reports_identity_stats(client):
    body = "? (10.0.7.50) at 00:0c:29:00:00:71 [ether] on eth0\n"
    r = client.post("/ingest/arp", files={"file": ("arp.txt", body.encode())})
    assert r.status_code == 200, r.text
    st = r.json()["stats"]
    assert st["hosts_renumbered"] == 1
    hosts = {h["mac"]: h for h in client.get("/hosts").json()}
    assert hosts["00:0c:29:00:00:71"]["ip"] == "10.0.7.50"
    hist = client.get(f"/hosts/{hosts['00:0c:29:00:00:71']['id']}/history").json()["history"]
    assert {h["ip"] for h in hist} == {"10.0.7.1", "10.0.7.9", "10.0.7.50"}
