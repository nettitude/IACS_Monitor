"""
Audit batch 2 (A): B-04, B-06, B-10, B-20.

B-04  pcap-based review_ns_* checks no longer skip whenever ANY FAZ event
      arrived; a session finding is suppressed only when the same flow is
      already reported by an active real-time finding backed by a recent
      permitted FAZ traffic event (same site).
B-06  topology diff evaluates every session (keyset batches); reviews
      paginate fully; any remaining cap is surfaced (last_review_info
      "truncated", compute_diff sessions_evaluated / truncated).
B-10  the PostgreSQL review advisory lock is taken and released on ONE
      dedicated connection held for the whole run.
B-20  internal / public address classification covers IPv6, ULA, CGNAT,
      link-local; unknown-Purdue skips are counted.
"""
from datetime import datetime, timedelta, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

import app.parsers.alert_engine as ae
import app.parsers.topology_diff as td
from app.db import Base, configure_sqlite_engine
from app.models import Finding, FortiAnalyzerEvent, Host, NetworkSession, Site

NOW = datetime.now(timezone.utc)


@pytest.fixture
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    configure_sqlite_engine(engine)
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()
    engine.dispose()


def site(db, code):
    s = Site(name=code.upper(), code=code)
    db.add(s)
    db.flush()
    return s.id


def host(db, ip, level=None, site_id=None, mac=None):
    h = Host(ip=ip, purdue_level=level, mac=mac, site_id=site_id)
    db.add(h)
    db.flush()
    return h


def sess(db, src, dst, port, transport="tcp", protocol="unknown"):
    s = NetworkSession(src_host_id=src.id, dst_host_id=dst.id, dst_port=port,
                       transport=transport, protocol=protocol, packet_count=5)
    db.add(s)
    db.flush()
    return s


def ev(db, src=None, dst=None, port=None, log_type="traffic", action="accept",
       site_id=None, protocol="tcp", received_at=None, **kw):
    e = FortiAnalyzerEvent(source_type="api_push", log_type=log_type, action=action,
                           src_ip=src, dst_ip=dst, dst_port=port, protocol=protocol,
                           device_name=kw.pop("device_name", "FGT1"),
                           received_at=received_at or NOW, raw_fields={},
                           site_id=site_id, **kw)
    db.add(e)
    db.flush()
    return e


def by_check(db, name, **flt):
    q = db.query(Finding).filter(Finding.check_name == name)
    return [f for f in q if all(f.detail.get(k) == v for k, v in flt.items())]


# ======================================================================= B-04

def _modbus_bypass(db, sid):
    it = host(db, "10.4.0.10", 4, site_id=sid)
    plc = host(db, "10.1.0.20", 1, site_id=sid)
    sess(db, it, plc, 502, protocol="modbus")
    return it, plc


def test_b04_unrelated_faz_event_does_not_silence_session_check(db):
    sid = site(db, "a")
    _modbus_bypass(db, sid)
    # an unrelated event log in the same site, received just now
    ev(db, log_type="event", subtype="system", action=None, protocol=None,
       src="10.9.9.9", dst=None, site_id=sid, device_name="other-fgt")
    ev(db, src="10.3.3.3", dst="10.3.3.4", port=443, site_id=sid)   # unrelated traffic
    db.commit()
    out = ae.review_ns_it_ot_bypass(db, site_id=sid)
    assert len(out) == 1 and out[0].detail["dst_port"] == 502
    # and through the full periodic run
    out[0].status = "closed"
    db.commit()
    ae.run_periodic_reviews(db, site_id=sid)
    assert len([f for f in by_check(db, "session_it_ot_bypass") if f.status == "open"]) == 1


def test_b04_matching_faz_traffic_event_gives_no_duplicate(db):
    sid = site(db, "a")
    _modbus_bypass(db, sid)
    e = ev(db, src="10.4.0.10", dst="10.1.0.20", port=502, site_id=sid)
    ae.evaluate_event(e, db)
    db.commit()
    assert len(by_check(db, "it_ot_bypass", dst_port=502)) == 1
    assert ae.review_ns_it_ot_bypass(db, site_id=sid) == []
    assert by_check(db, "session_it_ot_bypass") == []
    ae.run_periodic_reviews(db, site_id=sid)
    flow = [f for f in db.query(Finding)
            if f.detail.get("src_ip") == "10.4.0.10" and f.detail.get("dst_ip") == "10.1.0.20"
            and f.check_name in ("it_ot_bypass", "session_it_ot_bypass")]
    assert [f.check_name for f in flow] == ["it_ot_bypass"]


def test_b04_faz_event_alone_never_suppresses(db):
    """A matching but DENIED event (no real-time finding), a matching event
    for another port / transport, a stale one, or an RT finding in another
    site never hides the pcap-observed violation."""
    sid = site(db, "a")
    other = site(db, "b")
    _modbus_bypass(db, sid)
    ev(db, src="10.4.0.10", dst="10.1.0.20", port=502, action="deny", site_id=sid)
    # same flow fully reported in site B only
    host(db, "10.4.0.10", 4, site_id=other)
    host(db, "10.1.0.20", 1, site_id=other)
    eb = ev(db, src="10.4.0.10", dst="10.1.0.20", port=502, site_id=other)
    ae.evaluate_event(eb, db)
    db.commit()
    assert len(by_check(db, "it_ot_bypass")) == 1
    out = ae.review_ns_it_ot_bypass(db, site_id=sid)
    assert len(out) == 1 and out[0].site_id == sid


def test_b04_rt_finding_with_stale_or_mismatched_event_does_not_suppress(db):
    sid = site(db, "a")
    _modbus_bypass(db, sid)
    old = ev(db, src="10.4.0.10", dst="10.1.0.20", port=502, site_id=sid,
             received_at=NOW - timedelta(hours=ae._FAZ_RECENT_WINDOW_HOURS + 5))
    ae.evaluate_event(old, db)
    ev(db, src="10.4.0.10", dst="10.1.0.20", port=502, protocol="udp", site_id=sid)
    db.commit()
    assert len(by_check(db, "it_ot_bypass")) == 1
    assert len(ae.review_ns_it_ot_bypass(db, site_id=sid)) == 1


def test_b04_egress_and_remote_access_dedup_per_flow(db):
    plc = host(db, "10.1.0.5", 1)
    pub = host(db, "8.8.8.8")
    sess(db, plc, pub, 53, transport="udp")
    e = ev(db, src="10.1.0.5", dst="8.8.8.8", port=53, protocol="udp")
    ae.evaluate_event(e, db)
    db.commit()
    assert len(by_check(db, "ot_internet_egress")) == 1
    assert ae.review_ns_ot_internet_egress(db) == []
    sess(db, plc, host(db, "1.1.1.1"), 443)
    assert len(ae.review_ns_ot_internet_egress(db)) == 1   # other flow still raised

    ext = host(db, "198.51.100.7")
    srv = host(db, "10.4.0.30", 4)
    sess(db, ext, srv, 3389)
    ev(db, log_type="event", subtype="system", action=None, src="1.2.3.4")
    db.commit()
    assert len(ae.review_ns_remote_access_bypass(db)) == 1


# ======================================================================= B-06

def _diff_fixture(db, n):
    a, b = host(db, "10.2.0.5", 2), host(db, "10.1.0.9", 1)
    ids = [sess(db, a, b, 1000 + i).id for i in range(n)]
    db.commit()
    return ids


def test_b06_topology_diff_evaluates_all_sessions_in_batches(db, monkeypatch):
    ids = _diff_fixture(db, 7)
    monkeypatch.setattr(td, "SESSION_BATCH", 2)
    sizes = []
    real = td._iter_session_batches

    def spy(*a, **kw):
        for batch in real(*a, **kw):
            sizes.append(len(batch))
            yield batch
    monkeypatch.setattr(td, "_iter_session_batches", spy)
    r = td.compute_diff(db)
    assert r["sessions_total"] == r["sessions_evaluated"] == r["sessions_considered"] == 7
    assert r["sessions_truncated"] is False and r["truncated"] is False
    assert max(sizes) <= 2 and sum(sizes) == 7
    assert sorted(e["session_id"] for e in r["unexpected_traffic"]) == ids
    r3 = td.compute_diff(db, batch_size=3)
    assert r3["sessions_evaluated"] == 7


def test_b06_topology_diff_explicit_cap_is_reported(db):
    _diff_fixture(db, 7)
    r = td.compute_diff(db, session_limit=3, batch_size=2)
    assert r["sessions_total"] == 7 and r["sessions_evaluated"] == 3
    assert r["sessions_truncated"] is True and r["truncated"] is True


def test_b06_truncated_diff_surfaces_in_review_info_and_blocks_auto_resolve(db, monkeypatch):
    _diff_fixture(db, 5)
    real = td.compute_diff
    monkeypatch.setattr(td, "compute_diff", lambda d, **kw: real(d, session_limit=2))
    ae.run_periodic_reviews(db)
    info = ae.last_review_info()
    assert info["truncated"]["review_session_no_permitting_rule"] == {"topology diff sessions": 3}
    assert info["topology_diff"] == {"sessions_total": 5, "sessions_evaluated": 2,
                                     "sessions_truncated": True}
    monkeypatch.setattr(td, "compute_diff", real)
    ae.run_periodic_reviews(db)
    info = ae.last_review_info()
    assert info["truncated"] == {}
    assert info["topology_diff"]["sessions_evaluated"] == 5


def test_b06_reviews_paginate_fully(db, monkeypatch):
    monkeypatch.setattr(ae, "_PAGE_SIZE", 2)
    src = host(db, "10.3.0.1", 3)
    for i in range(7):
        sess(db, src, host(db, f"10.1.0.{10 + i}", 1), 23)     # cleartext to OT
    for i in range(5):                                         # mgmt from 2 levels
        d = host(db, f"10.2.0.{10 + i}", 2)
        sess(db, host(db, f"10.4.1.{i + 1}", 4), d, 22)
        sess(db, host(db, f"10.3.1.{i + 1}", 3), d, 22)
    db.commit()
    assert len(ae.review_cleartext_credentials(db)) == 7
    assert len(ae.review_mgmt_access_not_restricted(db)) == 5
    # unknown devices: every host (more than one page) is evaluated
    from app.models import ApprovedHost, Baseline
    b = Baseline(name="b", is_active=True)
    db.add(b)
    db.flush()
    db.add(ApprovedHost(baseline_id=b.id, ip="10.3.0.1", role="admin_ws"))
    db.commit()
    n_hosts = db.query(Host).count()
    assert len(ae.review_unknown_devices(db)) == n_hosts - 1
    ae.run_periodic_reviews(db)
    assert ae.last_review_info()["truncated"] == {}


def test_b06_limit_hit_records_truncation(db):
    db.info[ae._SEEN_KEY] = set()
    try:
        ae._limit_hit(db, [1, 2, 3], 3, "things")
        assert db.info[ae._TRUNCATED_KEY] == {"things": None}
        assert db.info[ae._INCOMPLETE_KEY]
    finally:
        for k in (ae._SEEN_KEY, ae._TRUNCATED_KEY, ae._INCOMPLETE_KEY):
            db.info.pop(k, None)


# ======================================================================= B-10

class _Result:
    def __init__(self, v):
        self.v = v

    def scalar(self):
        return self.v


class FakeConn:
    def __init__(self, engine):
        self.engine = engine
        self.calls = []
        self.closed = False

    def execute(self, stmt, params=None):
        sql = str(stmt)
        self.calls.append(sql)
        if "pg_try_advisory_lock" in sql:
            return _Result(self.engine.grant)
        if "pg_advisory_unlock" in sql:
            if self.engine.unlock_fails:
                raise RuntimeError("connection lost")
            return _Result(True)
        raise AssertionError(sql)

    def commit(self):
        self.calls.append("COMMIT")

    def invalidate(self):
        self.calls.append("INVALIDATE")

    def close(self):
        self.closed = True


class FakeEngine:
    def __init__(self, grant=True, unlock_fails=False):
        self.grant = grant
        self.unlock_fails = unlock_fails
        self.conns = []

    def connect(self):
        c = FakeConn(self)
        self.conns.append(c)
        return c


def _locks(conn):
    return [c for c in conn.calls if "advisory" in c]


def test_b10_lock_and_unlock_on_same_dedicated_connection(db, monkeypatch):
    eng = FakeEngine()
    monkeypatch.setattr(ae, "_pg_engine", lambda d: eng)
    ae.run_periodic_reviews(db, site_id=None)   # commits inside the run
    assert len(eng.conns) == 1
    conn = eng.conns[0]
    locks = _locks(conn)
    assert len(locks) == 2
    assert "pg_try_advisory_lock" in locks[0] and "pg_advisory_unlock" in locks[1]
    assert conn.closed


def test_b10_released_on_exception(db, monkeypatch):
    eng = FakeEngine()
    monkeypatch.setattr(ae, "_pg_engine", lambda d: eng)

    def boom(d):
        d.commit()
        raise RuntimeError("review crashed")
    monkeypatch.setattr(ae, "_run_periodic_reviews", boom)
    with pytest.raises(RuntimeError):
        ae.run_periodic_reviews(db, site_id=7)
    (conn,) = eng.conns
    assert "pg_advisory_unlock" in _locks(conn)[-1] and conn.closed
    # the in-process lock is free again: the next run is not skipped
    monkeypatch.undo()
    monkeypatch.setattr(ae, "_pg_engine", lambda d: FakeEngine())
    assert ae.REVIEW_SKIPPED_STAT not in ae.run_periodic_reviews(db, site_id=7)


def test_b10_lock_held_elsewhere_skips_and_closes(db, monkeypatch):
    eng = FakeEngine(grant=False)
    monkeypatch.setattr(ae, "_pg_engine", lambda d: eng)
    assert ae.run_periodic_reviews(db) == {ae.REVIEW_SKIPPED_STAT: 0}
    (conn,) = eng.conns
    assert len(_locks(conn)) == 1 and conn.closed


def test_b10_failed_unlock_invalidates_connection(db, monkeypatch):
    eng = FakeEngine(unlock_fails=True)
    monkeypatch.setattr(ae, "_pg_engine", lambda d: eng)
    monkeypatch.setattr(ae, "_run_periodic_reviews", lambda d: {})
    ae.run_periodic_reviews(db)
    (conn,) = eng.conns
    assert "INVALIDATE" in conn.calls and conn.closed


def test_b10_non_postgres_takes_no_lock(db):
    assert ae._pg_engine(db) is None
    assert ae._pg_try_lock(db) is None


# ======================================================================= B-20

@pytest.mark.parametrize("ip,internal,public", [
    ("10.0.0.1", True, False),
    ("100.64.1.1", True, False),          # CGNAT
    ("169.254.3.3", True, False),         # link-local v4
    ("fd00::10", True, False),            # ULA
    ("fe80::1", True, False),             # link-local v6
    ("::ffff:192.168.1.5", True, False),  # IPv4-mapped
    ("8.8.8.8", False, True),
    ("2001:4860:4860::8888", False, True),
    ("::ffff:8.8.8.8", False, True),
    ("239.1.1.1", False, False),          # multicast
    ("ff02::1", False, False),
    ("0.0.0.0", True, False),             # unspecified: never public
    (None, False, False),
    ("garbage", False, False),
])
def test_b20_address_classification(ip, internal, public):
    assert ae._is_internal_ip(ip) is internal
    assert ae._is_public_ip(ip) is public


@pytest.mark.parametrize("it_ip,ot_ip", [
    ("fd00:4::10", "fd00:1::20"),
    ("100.64.4.10", "100.64.1.20"),
    ("fe80::4", "fe80::1"),
])
def test_b20_it_ot_bypass_realtime_on_v6_ula_cgnat_linklocal(db, it_ip, ot_ip):
    host(db, it_ip, 4)
    host(db, ot_ip, 1)
    f = ae.check_it_ot_bypass(ev(db, src=it_ip, dst=ot_ip, port=502), db)
    assert f is not None and f.detail["detection"] == "purdue_level"


def test_b20_it_ot_bypass_heuristic_ipv6(db):
    f = ae.check_it_ot_bypass(ev(db, src="fd00:1:1::5", dst="fd00:2:2::5", port=502), db)
    assert f is not None and f.detail["detection"] == "subnet_heuristic"
    assert ae.check_it_ot_bypass(ev(db, src="fd00:1:1::5", dst="fd00:1:1:9::5", port=502),
                                 db) is None


@pytest.mark.parametrize("src,dst,fires", [
    ("fd00:1::5", "2001:4860:4860::8888", True),
    ("100.64.1.5", "8.8.8.8", True),
    ("fe80::5", "2606:4700::1111", True),
    ("10.1.0.5", "fe80::1", False),       # link-local dst is not 'public'
    ("10.1.0.5", "100.64.0.1", False),    # CGNAT dst is not 'public'
    ("10.1.0.5", "239.1.1.1", False),     # multicast
])
def test_b20_ot_internet_egress_realtime(db, src, dst, fires):
    host(db, src, 1)
    f = ae.check_ot_internet_egress(ev(db, src=src, dst=dst, port=443), db)
    assert (f is not None) is fires
    if fires:
        assert f.severity == "critical"


def test_b20_session_reviews_ipv6(db):
    it, ot = host(db, "fd00:4::10", 4), host(db, "fd00:1::20", 1)
    sess(db, it, ot, 502)
    assert len(ae.review_ns_it_ot_bypass(db)) == 1
    sess(db, ot, host(db, "2001:4860:4860::8888"), 443)
    sess(db, ot, host(db, "fe80::99"), 443)
    sess(db, ot, host(db, "100.64.9.9"), 443)
    out = ae.review_ns_ot_internet_egress(db)
    assert [f.detail["dst_ip"] for f in out] == ["2001:4860:4860::8888"]
    # remote access: CGNAT / link-local sources are internal, global v6 is external
    sess(db, host(db, "2a00:1450::1"), host(db, "fd00:4::30", 4), 3389)
    sess(db, host(db, "100.64.5.5"), host(db, "fd00:4::31", 4), 3389)
    out = ae.review_ns_remote_access_bypass(db)
    assert [f.detail["src_ip"] for f in out] == ["2a00:1450::1"]


def test_b20_unknown_level_skips_counted_and_scoped_auto_resolve(db):
    a, b = host(db, "10.3.0.1", 3), host(db, "10.1.0.1", 1)
    c, d = host(db, "10.3.0.2", 3), host(db, "10.1.0.2", 1)
    sess(db, a, b, 23, protocol="telnet")
    s2 = sess(db, c, d, 23, protocol="telnet")
    db.commit()
    ae.run_periodic_reviews(db)
    assert len([f for f in by_check(db, "cleartext_protocol") if f.status == "open"]) == 2
    assert "review_cleartext_protocols" not in ae.last_review_info()["skipped_unknown_level"]
    b.purdue_level = None       # flow 1 can no longer be evaluated
    s2.dst_port = 22            # flow 2 is gone (no longer insecure)
    db.commit()
    ae.run_periodic_reviews(db)
    info = ae.last_review_info()
    assert info["skipped_unknown_level"]["review_cleartext_protocols"] == 1
    st = {f.detail["dst_ip"]: f.status for f in by_check(db, "cleartext_protocol")}
    assert st == {"10.1.0.1": "open", "10.1.0.2": "closed"}


def test_b20_ns_reviews_count_unknown_level(db):
    it, unk = host(db, "10.4.0.1", 4), host(db, "10.1.0.77", None)
    sess(db, it, unk, 502)
    sess(db, unk, host(db, "8.8.4.4"), 443)
    db.commit()
    ae.run_periodic_reviews(db)
    sk = ae.last_review_info()["skipped_unknown_level"]
    assert sk["review_ns_it_ot_bypass"] == 2      # both sessions touch the unknown host
    assert sk["review_ns_ot_internet_egress"] == 1
