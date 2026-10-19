"""Regression tests: audit batch 2 (B) - B-09, B-14, B-16."""
import sqlite3
import threading
import time
from datetime import datetime, timezone

import pytest
from fastapi import Depends, FastAPI
from fastapi.testclient import TestClient
from scapy.all import Ether, IP, UDP, Raw, wrpcap
from sqlalchemy import create_engine, text
from sqlalchemy.exc import OperationalError
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.db as db_mod
from app.api import routes
from app.models import (
    Base, Finding, Firewall, FirewallInterface, FirewallZone, Host, MacTableEntry,
    NetworkSession, ProtocolDetail, Site,
)
from app.parsers.cross_fw_findings import _upsert_finding
from app.parsers.host_identity import is_unicast_host_ip, site_broadcast_addresses
from app.parsers.mac_table_parser import ingest_mac_table, parse_cisco_mac_table, parse_hp_mac_table
from app.parsers.pcap_parser import GROUP_MARKER_MAC, dnp3_crc, ingest_pcap, is_group_marker_host
from app.parsers.site_scope import analysis_site
from app.parsers.traffic_findings import check_unauthorized_industrial_writes

from tests.test_cov_routes import _api, up


def _locked_exc():
    return OperationalError("INSERT ...", {}, sqlite3.OperationalError("database is locked"))


# =============================================================== B-09 ===

@pytest.fixture
def file_engine(tmp_path):
    eng = db_mod.make_engine(f"sqlite:///{tmp_path / 'b09.db'}")
    with eng.begin() as c:
        c.exec_driver_sql("CREATE TABLE t (id INTEGER PRIMARY KEY, v TEXT)")
    yield eng
    eng.dispose()


def test_deferred_begin_loses_upgrade_after_concurrent_commit(file_engine):
    """The B-09 mechanism: a deferred transaction that read first cannot
    write once another connection committed (SQLITE_BUSY_SNAPSHOT is not
    retried by busy_timeout) - why write sessions use BEGIN IMMEDIATE."""
    Read = sessionmaker(bind=file_engine)
    a, b = Read(), Read()
    try:
        a.execute(text("SELECT count(*) FROM t")).scalar()      # snapshot taken
        b.execute(text("INSERT INTO t (v) VALUES ('short')"))
        b.commit()
        t0 = time.perf_counter()
        with pytest.raises(OperationalError, match="locked|busy"):
            a.execute(text("INSERT INTO t (v) VALUES ('long')"))
        assert time.perf_counter() - t0 < 5            # immediate, busy_timeout useless
    finally:
        a.rollback(); a.close(); b.close()


def test_immediate_long_writer_and_short_writer_both_succeed(file_engine):
    Write = sessionmaker(bind=db_mod.write_engine(file_engine))
    started, errors, order = threading.Event(), [], []

    def long_writer():
        s = Write()
        try:
            s.execute(text("SELECT count(*) FROM t")).scalar()   # read first, like ingest
            started.set()
            s.execute(text("INSERT INTO t (v) VALUES ('long-1')"))
            time.sleep(0.8)                                       # "parsing"
            s.execute(text("INSERT INTO t (v) VALUES ('long-2')"))
            s.commit()
            order.append("long")
        except Exception as exc:  # pragma: no cover - the failure being tested
            errors.append(exc)
        finally:
            s.close()

    def short_writer():
        started.wait(5)
        s = Write()
        try:
            s.execute(text("INSERT INTO t (v) VALUES ('short')"))
            s.commit()
            order.append("short")
        except Exception as exc:  # pragma: no cover
            errors.append(exc)
        finally:
            s.close()

    ts = [threading.Thread(target=long_writer), threading.Thread(target=short_writer)]
    for t in ts:
        t.start()
    for t in ts:
        t.join(30)
    assert not errors, errors
    assert order == ["long", "short"]                # the short writer queued
    with file_engine.connect() as c:
        assert c.exec_driver_sql("SELECT count(*) FROM t").scalar() == 3


def test_busy_timeout_env_configurable(tmp_path, monkeypatch):
    monkeypatch.setenv("IACS_SQLITE_BUSY_TIMEOUT_MS", "1234")
    eng = db_mod.make_engine(f"sqlite:///{tmp_path / 'bt.db'}")
    try:
        with eng.connect() as c:
            assert c.exec_driver_sql("PRAGMA busy_timeout").scalar() == 1234
    finally:
        eng.dispose()
    monkeypatch.setenv("IACS_SQLITE_BUSY_TIMEOUT_MS", "junk")
    assert db_mod.sqlite_busy_timeout_ms() == 30000


def test_begin_statement_per_session_kind(file_engine):
    from sqlalchemy import event
    seen = []

    @event.listens_for(file_engine, "before_cursor_execute")
    def _rec(conn, cur, stmt, *a):
        if stmt.startswith("BEGIN"):
            seen.append(stmt)

    for factory in (sessionmaker(bind=file_engine),
                    sessionmaker(bind=db_mod.write_engine(file_engine))):
        s = factory()
        s.execute(text("SELECT 1"))
        s.close()
    assert seen[-2:] == ["BEGIN", "BEGIN IMMEDIATE"]


def test_get_db_picks_write_session_for_mutating_methods(monkeypatch):
    calls = []
    monkeypatch.setattr(db_mod, "SessionLocal", lambda: calls.append("read") or _Dummy())
    monkeypatch.setattr(db_mod, "WriteSessionLocal", lambda: calls.append("write") or _Dummy())
    app = FastAPI()

    @app.api_route("/x", methods=["GET", "POST", "PATCH", "DELETE"])
    def x(db=Depends(db_mod.get_db)):
        return {}

    with TestClient(app) as c:
        for m in ("GET", "POST", "PATCH", "DELETE"):
            assert c.request(m, "/x").status_code == 200
    assert calls == ["read", "write", "write", "write"]
    gen = db_mod.get_db()                      # direct call (no request): deferred
    next(gen)
    assert calls[-1] == "read"
    gen.close()


class _Dummy:
    def rollback(self):
        pass

    def close(self):
        pass


def test_locked_operational_error_maps_to_503():
    app = FastAPI()
    from fastapi import APIRouter
    r = APIRouter(route_class=routes._RangeSafeRoute)

    @r.post("/boom")
    def boom():
        raise _locked_exc()

    @r.post("/other")
    def other():
        raise OperationalError("SELECT", {}, sqlite3.OperationalError("no such table: x"))

    app.include_router(r)
    with TestClient(app, raise_server_exceptions=False) as c:
        resp = c.post("/boom")
        assert resp.status_code == 503 and resp.headers.get("retry-after")
        assert c.post("/other").status_code == 500       # only lock errors are 503
    h = routes._internal_error(_locked_exc(), "Failed; nothing was stored", status_code=400)
    assert h.status_code == 503 and h.headers["Retry-After"]


def test_pcap_ingest_lock_error_is_503_not_400(tmp_path, monkeypatch):
    def _raise(*a, **k):
        raise _locked_exc()

    monkeypatch.setattr(routes, "ingest_pcap", _raise)
    with _api(tmp_path / "lock.db") as c:
        with c.Session() as s:
            s.add(Site(name="Default", code="default")); s.commit()
        r = up(c, "/ingest/pcap", "modbus_sample.pcap")
        assert r.status_code == 503, r.text
        assert r.headers.get("retry-after")
        assert "nothing was stored" in r.json()["detail"]


# =============================================================== B-14 ===

@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    s.add(Site(name="Plant", code="plant"))
    s.commit()
    yield s
    s.close()


def _sid(db):
    return db.query(Site).filter_by(code="plant").one().id


A, B = "00:1b:1b:00:00:0a", "00:0e:8c:00:00:0b"


def _link(user: bytes, src=1, dst=10) -> bytes:
    hdr = b"\x05\x64" + bytes([5 + len(user), 0xC4]) + dst.to_bytes(2, "little") + src.to_bytes(2, "little")
    out = hdr + dnp3_crc(hdr).to_bytes(2, "little")
    for i in range(0, len(user), 16):
        ch = user[i:i + 16]
        out += ch + dnp3_crc(ch).to_bytes(2, "little")
    return out


_WRITE = _link(bytes([0xC0, 0xC2, 0x02, 12, 1, 0x28, 1, 0, 0, 0, 0x41, 1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0]))


def _pcap(tmp_path, pkts, name="t.pcap"):
    for i, p in enumerate(pkts):
        p.time = 1_700_000_000.0 + i * 0.001
    path = str(tmp_path / name)
    wrpcap(path, pkts)
    return path


def _udp(dst, dmac, payload=_WRITE, src="10.0.0.1", smac=A, sport=40000, dport=20000):
    return Ether(src=smac, dst=dmac) / IP(src=src, dst=dst) / UDP(sport=sport, dport=dport) / Raw(payload)


def test_broadcast_and_multicast_dnp3_write_decoded_and_flagged(db, tmp_path):
    sid = _sid(db)
    pkts = [_udp("10.0.0.255", "ff:ff:ff:ff:ff:ff"),           # directed broadcast
            _udp("255.255.255.255", "ff:ff:ff:ff:ff:ff"),      # limited broadcast
            _udp("239.1.1.1", "01:00:5e:01:01:01")]            # multicast
    stats = ingest_pcap(_pcap(tmp_path, pkts), db, site_id=sid)
    assert stats["protocol_frames"]["dnp3"] == 3
    assert stats["dnp3_group_packets"] == 3
    ips = {h.ip for h in db.query(Host).all()}
    assert ips == {"10.0.0.1", None}                    # sender + the group marker only
    marker = db.query(Host).filter(Host.ip.is_(None)).one()
    assert marker.mac == GROUP_MARKER_MAC and is_group_marker_host(marker) and marker.site_id == sid
    sess = db.query(NetworkSession).one()
    assert sess.dst_host_id == marker.id and sess.protocol == "dnp3"
    details = db.query(ProtocolDetail).all()
    assert {d.fields["dst_group"] for d in details} == {"10.0.0.255", "255.255.255.255", "239.1.1.1"}
    assert all(d.fields["operation"] == "write" for d in details)

    out = check_unauthorized_industrial_writes(db, commit=False, site_id=sid)
    assert out["findings_created"] == 1
    f = db.query(Finding).filter_by(check_name="unauthorized_industrial_write").one()
    assert f.detail["src_ip"] == "10.0.0.1" and f.detail["occurrences"] == 3

    # Re-ingest: still one marker per site.
    ingest_pcap(_pcap(tmp_path, pkts, "t2.pcap"), db, site_id=sid)
    assert db.query(Host).filter(Host.mac == GROUP_MARKER_MAC).count() == 1


def test_marker_not_reclassified(db, tmp_path):
    from app.parsers.device_classification import classify_hosts
    sid = _sid(db)
    ingest_pcap(_pcap(tmp_path, [_udp("10.0.0.255", "ff:ff:ff:ff:ff:ff")]), db, site_id=sid)
    classify_hosts(db, site_id=sid)
    marker = db.query(Host).filter(Host.mac == GROUP_MARKER_MAC).one()
    assert marker.device_type is None and marker.classification_source == "manual"


def test_is_unicast_host_ip_group_mac_and_broadcasts():
    assert is_unicast_host_ip("10.0.0.255")
    assert not is_unicast_host_ip("10.0.0.255", "ff:ff:ff:ff:ff:ff")
    assert not is_unicast_host_ip("10.0.0.7", "01:00:5e:00:00:07")
    assert not is_unicast_host_ip("10.0.0.255", B, {"10.0.0.255"})
    assert is_unicast_host_ip("10.0.0.2", B, {"10.0.0.255"})
    assert not is_unicast_host_ip("255.255.255.255")


def test_directed_broadcast_by_known_subnet_no_phantom_host(db, tmp_path):
    sid = _sid(db)
    fw = Firewall(site_id=sid, name="FW1")
    db.add(fw); db.flush()
    db.add(FirewallInterface(firewall_id=fw.id, name="port1", ip_address="10.0.0.1",
                             prefix_len=24, ip_cidr="10.0.0.1/24"))
    db.add(FirewallZone(site_id=sid, interface_name="p2", ip_cidr="172.16.4.1/22"))
    other = Site(name="Other", code="other")
    db.add(other); db.flush()
    db.add(FirewallZone(site_id=other.id, interface_name="p9", ip_cidr="192.168.9.1/24"))
    db.commit()
    assert site_broadcast_addresses(db, sid) == {"10.0.0.255", "172.16.7.255"}

    # Unicast dst MAC (e.g. a router forwarding a directed broadcast).  Syslog
    # (one-way): RS-02 - a destination of an unanswered request is no host.
    pkts = [_udp("10.0.0.255", B, payload=b"hello", dport=514),
            _udp("172.16.7.255", B, payload=b"hello", dport=514),
            _udp("192.168.9.255", B, payload=b"hello", dport=514),   # other site's subnet
            _udp("10.0.0.2", B, payload=b"hello", dport=514)]
    stats = ingest_pcap(_pcap(tmp_path, pkts), db, site_id=sid)
    ips = {h.ip for h in db.query(Host).filter(Host.site_id == sid).all()}
    assert "10.0.0.255" not in ips and "172.16.7.255" not in ips
    assert {"10.0.0.1", "10.0.0.2", "192.168.9.255"} <= ips
    assert stats["ipv4_directed_broadcast_packets"] == 2


def test_directed_broadcast_by_group_mac_without_subnet(db, tmp_path):
    sid = _sid(db)
    pkts = [_udp("192.168.5.255", "ff:ff:ff:ff:ff:ff", payload=b"x", dport=5000, src="192.168.5.3")]
    ingest_pcap(_pcap(tmp_path, pkts), db, site_id=sid)
    assert {h.ip for h in db.query(Host).all()} == {"192.168.5.3"}
    assert db.query(NetworkSession).count() == 0


CISCO_TABLE = """\
          Mac Address Table
-------------------------------------------
Vlan    Mac Address       Type        Ports
----    -----------       --------    -----
 All    0100.0ccc.cccc    STATIC      CPU
  10    0100.0ccc.cccd    STATIC      Gi1/0/1
  10    ffff.ffff.ffff    STATIC      Gi1/0/1
  10    0011.2233.4455    STATIC      CPU
  10    0011.2233.4466    DYNAMIC     Gi1/0/2
  20    0011.2233.4477    STATIC      Gi1/0/3
  20    0011.2233.4477    STATIC      Gi1/0/3
"""


def test_mac_table_skips_group_and_cpu_rows():
    macs = [e["mac"] for e in parse_cisco_mac_table(CISCO_TABLE)]
    assert macs == ["00:11:22:33:44:66", "00:11:22:33:44:77", "00:11:22:33:44:77"]
    hp = ("001122-334455   5   10\n"
          "01005e-000001   5   10\n"
          "ffffff-ffffff   CPU 10\n")
    assert [e["mac"] for e in parse_hp_mac_table(hp)] == ["00:11:22:33:44:55"]


def test_mac_table_reingest_does_not_duplicate(db):
    sid = _sid(db)
    s1 = ingest_mac_table(CISCO_TABLE, db, device_name="SW1", source_file="a.txt", site_id=sid)
    assert db.query(MacTableEntry).count() == 2          # duplicate line collapsed
    assert s1["entries_inserted"] == 2
    s2 = ingest_mac_table(CISCO_TABLE, db, device_name="SW1", source_file="b.txt", site_id=sid)
    assert db.query(MacTableEntry).count() == 2
    assert s2["entries_inserted"] == 0 and s2["entries_updated"] == 3
    assert {r.source_file for r in db.query(MacTableEntry)} == {"b.txt"}
    # A different device / vlan / port is a different row.
    ingest_mac_table(CISCO_TABLE, db, device_name="SW2", site_id=sid)
    ingest_mac_table("  30    0011.2233.4466    DYNAMIC     Gi1/0/2\n", db, device_name="SW1",
                     site_id=sid)
    assert db.query(MacTableEntry).count() == 5
    assert not db.query(Host).filter(Host.mac.like("01:%")).count()
    assert not db.query(Host).filter(Host.mac == "ff:ff:ff:ff:ff:ff").count()


# =============================================================== B-16 ===

def _finding(s, site_id, status="open", ref="ref:1", **kw):
    f = Finding(site_id=site_id, category="periodic_review", check_name="x", severity="high",
                status=status, title="t", source_ref=ref, **kw)
    s.add(f); s.commit()
    return f.id


@pytest.fixture
def fclient(tmp_path):
    with _api(tmp_path / "b16.db") as c:
        with c.Session() as s:
            site = Site(name="Default", code="default")
            s.add(site); s.commit()
            c.site_id = site.id
        yield c


def test_reopen_with_open_recurrence_is_409(fclient):
    c = fclient
    with c.Session() as s:
        old = _finding(s, c.site_id, status="closed", closed_at=datetime.now(timezone.utc))
        cur = _finding(s, c.site_id, status="open")
    r = c.patch(f"/findings/{old}/status", params={"status": "open"})
    assert r.status_code == 409, r.text
    assert r.json()["detail"]["open_finding_id"] == cur
    with c.Session() as s:
        assert s.get(Finding, old).status == "closed"


def test_reopen_clears_ack_and_closed_at(fclient):
    c = fclient
    with c.Session() as s:
        fid = _finding(s, c.site_id)
    assert c.patch(f"/findings/{fid}/status",
                   params={"status": "acknowledged", "acknowledged_by": "alice"}).status_code == 200
    assert c.patch(f"/findings/{fid}/status", params={"status": "closed"}).status_code == 200
    with c.Session() as s:
        f = s.get(Finding, fid)
        assert f.acknowledged_by == "alice" and f.acknowledged_at and f.closed_at
    assert c.patch(f"/findings/{fid}/status", params={"status": "open"}).status_code == 200
    with c.Session() as s:
        f = s.get(Finding, fid)
        assert (f.status, f.acknowledged_by, f.acknowledged_at, f.closed_at) == ("open", None, None, None)
    # ack after close clears closed_at
    c.patch(f"/findings/{fid}/status", params={"status": "closed"})
    c.patch(f"/findings/{fid}/status", params={"status": "acknowledged", "acknowledged_by": "bob"})
    with c.Session() as s:
        f = s.get(Finding, fid)
        assert f.closed_at is None and f.acknowledged_by == "bob"


def test_status_validation_422(fclient):
    c = fclient
    with c.Session() as s:
        fid = _finding(s, c.site_id)
    p = f"/findings/{fid}/status"
    assert c.patch(p, params={"status": "deleted"}).status_code == 422
    assert c.patch(p, params={"status": "acknowledged"}).status_code == 422
    assert c.patch(p, params={"status": "acknowledged", "acknowledged_by": "   "}).status_code == 422
    assert c.patch(p, params={"status": "closed", "notes": "x" * 2049}).status_code == 422
    assert c.patch(p, params={"status": "acknowledged", "acknowledged_by": "a" * 129}).status_code == 422
    assert c.patch(p, params={"status": "closed", "notes": "x" * 2048}).status_code == 200
    # already acknowledged by someone: a notes edit without re-typing the name is fine
    assert c.patch(p, params={"status": "acknowledged", "acknowledged_by": "carol"}).status_code == 200
    assert c.patch(p, params={"status": "acknowledged", "notes": "n"}).status_code == 200
    with c.Session() as s:
        assert s.get(Finding, fid).acknowledged_by == "carol"


def test_cross_fw_upsert_reopen_clears_ack(db):
    sid = _sid(db)
    now = datetime.now(timezone.utc)
    f = Finding(site_id=sid, category="config_review", check_name="cross_fw_no_rules",
                severity="high", status="closed", title="old", source_ref="xfw:1",
                acknowledged_by="alice", acknowledged_at=now, closed_at=now)
    db.add(f); db.commit()
    with analysis_site(db, sid):
        out = _upsert_finding(db, category="config_review", check_name="cross_fw_no_rules",
                              severity="high", title="new", source_ref="xfw:1")
    assert out is f and f.status == "open"
    assert (f.acknowledged_by, f.acknowledged_at, f.closed_at) == (None, None, None)
    db.commit()


def test_cross_fw_upsert_skips_when_any_recurrence_active(db):
    sid = _sid(db)
    old = Finding(site_id=sid, category="config_review", severity="high", status="closed",
                  title="old", source_ref="xfw:2")
    db.add(old); db.commit()
    db.add(Finding(site_id=sid, category="config_review", severity="high", status="open",
                   title="cur", source_ref="xfw:2"))
    db.commit()
    with analysis_site(db, sid):
        assert _upsert_finding(db, category="config_review", severity="high", title="n",
                               source_ref="xfw:2") is None
    db.commit()                                     # no IntegrityError
    assert old.status == "closed"
