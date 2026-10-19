"""
Follow-up fixes:

1. B-08 regression - pcap host creation race.  The pcap fast path inserts
   hosts it believes are new (in-memory site ip/mac sets) without a lookup;
   a host inserted meanwhile by another transaction used to fail the whole
   ingest with a unique-index IntegrityError on PostgreSQL.  Now:
   common.insert_host_row = INSERT ... ON CONFLICT DO NOTHING RETURNING,
   then re-select with the get_or_create_host rules; and pcap ingests of the
   same site serialise on a PostgreSQL advisory lock.
2. cross_fw_findings source_ref: both firewall ids (directional a>b), the
   VDOM and the policy id, so same-numbered policies of the two firewalls of
   a pair no longer merge; auto-resolve still closes them.

PostgreSQL tests use IACS_TEST_PG_URL when set, else try to start a
throwaway local cluster (initdb / pg_ctl of the postgresql package); they
are skipped when neither is possible.
"""
import glob
import os
import shutil
import socket
import subprocess
import tempfile
import threading
import time
from datetime import datetime, timezone
from pathlib import Path

import pytest
from scapy.all import IP, TCP, Ether, Raw, wrpcap
from sqlalchemy import create_engine, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import NullPool

import app.parsers.pcap_parser as pp
from app.db import Base, make_engine
from app.models import Finding, Firewall, FirewallInterface, FirewallRule, Host, NetworkSession, Site
from app.parsers import common
from app.parsers.cross_fw_findings import run_cross_fw_checks
from app.parsers.pcap_parser import ingest_pcap
from app.sites import get_default_site

MAC_SRV = "00:aa:bb:cc:dd:ee"
T0 = datetime(2026, 1, 1, tzinfo=timezone.utc)


# ================================================================ helpers ==

def _pkt(i, mac=None, ip=None):
    p = (Ether(src=mac or "02:00:00:00:%02x:%02x" % (i >> 8 & 255, i & 255), dst=MAC_SRV)
         / IP(src=ip or f"10.9.{i // 250}.{i % 250 + 1}", dst="10.0.0.1")
         / TCP(sport=40000 + i % 20000, dport=502, flags="PA", seq=1000)
         / Raw(b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x01"))
    p.time = 1_700_000_000 + i * 0.01
    return p


def _pcap(tmp_path, n, name="t.pcap", **kw):
    path = tmp_path / name
    wrpcap(str(path), [_pkt(i, **kw) for i in range(n)])
    return str(path)


def _identities(s):
    return sorted((h.site_id, h.ip, h.mac) for h in s.query(Host))


def _assert_no_duplicate_hosts(s):
    ids = _identities(s)
    assert len(ids) == len(set(ids)), "duplicate host identities"


# ------------------------------------------------------------ PostgreSQL --

def _free_port():
    with socket.socket() as so:
        so.bind(("127.0.0.1", 0))
        return so.getsockname()[1]


def _pg_bindir():
    for c in [os.path.dirname(shutil.which("pg_ctl") or "")] + sorted(
            glob.glob("/usr/lib/postgresql/*/bin"), reverse=True):
        if c and os.path.exists(os.path.join(c, "initdb")) and os.path.exists(os.path.join(c, "pg_ctl")):
            return c
    return None


@pytest.fixture(scope="module")
def pg_url():
    url = os.environ.get("IACS_TEST_PG_URL")
    if url:
        yield url
        return
    pytest.importorskip("psycopg2")
    bindir = _pg_bindir()
    if not bindir:
        pytest.skip("no PostgreSQL server binaries (initdb/pg_ctl)")
    root = tempfile.mkdtemp(prefix="iasc_pg_")
    prefix = []
    if os.geteuid() == 0:              # initdb refuses to run as root
        if not shutil.which("runuser"):
            pytest.skip("running as root without runuser")
        try:
            shutil.chown(root, "postgres", "postgres")
        except (LookupError, PermissionError, OSError):
            pytest.skip("no postgres OS user")
        prefix = ["runuser", "-u", "postgres", "--"]
    data, port = os.path.join(root, "data"), _free_port()

    def run(*args):
        return subprocess.run(prefix + list(args), capture_output=True, text=True, timeout=120)

    r = run(os.path.join(bindir, "initdb"), "-D", data, "-A", "trust", "-U", "iasc", "--no-sync")
    if r.returncode:
        shutil.rmtree(root, ignore_errors=True)
        pytest.skip(f"initdb failed: {r.stderr[-300:]}")
    r = run(os.path.join(bindir, "pg_ctl"), "-D", data, "-w", "-l", os.path.join(root, "log"),
            "-o", f"-p {port} -k {root} -c listen_addresses=127.0.0.1 -F", "start")
    if r.returncode:
        shutil.rmtree(root, ignore_errors=True)
        pytest.skip(f"pg_ctl start failed: {r.stderr[-300:]}")
    try:
        admin = create_engine(f"postgresql+psycopg2://iasc@127.0.0.1:{port}/postgres",
                              isolation_level="AUTOCOMMIT")
        with admin.connect() as c:
            c.execute(text("CREATE DATABASE iasc_test"))
        admin.dispose()
        yield f"postgresql+psycopg2://iasc@127.0.0.1:{port}/iasc_test"
    finally:
        run(os.path.join(bindir, "pg_ctl"), "-D", data, "-m", "immediate", "stop")
        shutil.rmtree(root, ignore_errors=True)


@pytest.fixture
def pg(pg_url):
    """Fresh schema on the PostgreSQL server -> engine."""
    eng = create_engine(pg_url, poolclass=NullPool)
    Base.metadata.drop_all(eng)
    Base.metadata.create_all(eng)
    with sessionmaker(bind=eng)() as s:
        get_default_site(s)
        s.commit()
    yield eng
    eng.dispose()


@pytest.fixture
def lite(tmp_path):
    eng = make_engine(f"sqlite:///{tmp_path / 'race.db'}")
    Base.metadata.create_all(eng)
    with sessionmaker(bind=eng)() as s:
        get_default_site(s)
        s.commit()
    yield eng
    eng.dispose()


# ====================================== 1a. insert_host_row on a conflict ==

def _site_id(eng):
    with sessionmaker(bind=eng)() as s:
        return get_default_site(s).id


def _insert_elsewhere(eng, **cols):
    """Commit a Host row through a different connection / transaction."""
    with eng.begin() as c:
        c.execute(Host.__table__.insert().values(
            first_seen=T0, last_seen=T0, stale=False, **cols))


@pytest.mark.parametrize("ip,mac", [("10.1.1.1", "02:00:00:00:00:01"),
                                    ("10.1.1.2", None), (None, "02:00:00:00:00:03")])
@pytest.mark.parametrize("backend", ["sqlite", "postgresql"])
def test_insert_host_row_reuses_concurrently_inserted_row(request, backend, ip, mac):
    eng = request.getfixturevalue("lite" if backend == "sqlite" else "pg")
    sid = _site_id(eng)
    s = sessionmaker(bind=eng, autoflush=False)()
    try:
        s.query(Host).count()       # our transaction is open (snapshot / cache warm)
        if backend == "sqlite":
            # SQLite serialises writers (BEGIN IMMEDIATE): the only way a row
            # can appear is through our own connection, behind the cache.
            s.execute(Host.__table__.insert().values(
                site_id=sid, ip=ip, mac=mac, sources=["arp"], first_seen=T0,
                last_seen=T0, stale=False))
        else:
            _insert_elsewhere(eng, site_id=sid, ip=ip, mac=mac, sources=["arp"])
        host, created = common.insert_host_row(s, ip, mac, "pcap", T0.replace(year=2027), sid)
        assert created is False
        assert set(host.sources) == {"arp", "pcap"}
        assert host.last_seen.year == 2027
        s.commit()
        assert s.query(Host).count() == 1
        # no conflict -> a fresh row, created=True, fully loaded (no expired attrs)
        h2, created2 = common.insert_host_row(s, "10.7.7.7", "02:00:00:00:07:07", "pcap", T0, sid)
        assert created2 is True and h2.id and h2.sources == ["pcap"] and h2.vlan is None
        s.commit()
        assert s.query(Host).count() == 2
    finally:
        s.close()


# ================================= 1b. pcap ingest, row inserted mid-ingest ==

def _patch_first_insert(monkeypatch, hook):
    real = pp.insert_host_row
    calls = {"n": 0}

    def wrapper(db, ip, mac, *a, **kw):
        calls["n"] += 1
        if calls["n"] == 1:
            hook(db, ip, mac)
        return real(db, ip, mac, *a, **kw)
    monkeypatch.setattr(pp, "insert_host_row", wrapper)
    return calls


@pytest.mark.parametrize("backend", ["sqlite", "postgresql"])
def test_pcap_ingest_survives_host_inserted_after_cache_warmed(request, backend, tmp_path, monkeypatch):
    eng = request.getfixturevalue("lite" if backend == "sqlite" else "pg")
    sid = _site_id(eng)
    path = _pcap(tmp_path, 20)
    seen = {}

    def hook(db, ip, mac):
        # The first host the fast path is about to insert appears now, after
        # the site ip/mac sets and the host cache were loaded.
        seen["key"] = (ip, mac)
        row = dict(site_id=sid, ip=ip, mac=mac, sources=["arp"])
        if backend == "sqlite":
            db.execute(Host.__table__.insert().values(first_seen=T0, last_seen=T0, stale=False, **row))
        else:
            _insert_elsewhere(eng, **row)
    calls = _patch_first_insert(monkeypatch, hook)

    s = sessionmaker(bind=eng, autoflush=False)()
    try:
        stats = ingest_pcap(path, s)
        assert calls["n"] >= 20
        assert stats["host_insert_conflicts"] == 1
        assert stats["hosts"] == 20       # 21 hosts seen, the conflicting one existed
        _assert_no_duplicate_hosts(s)
        assert s.query(Host).count() == 21
        ip, mac = seen["key"]
        (h,) = s.query(Host).filter(Host.ip == ip, Host.mac == mac).all()
        assert set(h.sources) == {"arp", "pcap"}       # the existing row was used
        assert s.query(NetworkSession).filter(NetworkSession.src_host_id == h.id).count() == 1
    finally:
        s.close()


def test_conflict_reselect_applies_identity_rules(lite):
    """The conflict re-select is get_or_create_host's matcher: an ip+mac
    insert that loses to an ip+mac row of the same identity reuses it, and
    a pending MAC attached to an IP-only row is flushed before the insert
    (so ON CONFLICT sees it instead of the insert creating a duplicate)."""
    sid = _site_id(lite)
    s = sessionmaker(bind=lite, autoflush=False)()
    try:
        ip_only = Host(site_id=sid, ip="10.2.2.2", mac=None, sources=["config"])
        s.add(ip_only)
        s.commit()
        common.refresh_host(ip_only, "10.2.2.2", "02:00:00:00:02:02", "arp", T0)   # pending
        host, created = common.insert_host_row(s, "10.2.2.2", "02:00:00:00:02:02", "pcap", T0, sid)
        assert created is False and host is ip_only
        assert set(host.sources) == {"config", "arp", "pcap"}
        s.commit()
        assert s.query(Host).count() == 1
    finally:
        s.close()


# ======================================== 1c. two concurrent pcap ingests ==

def _concurrent_ingests(eng, paths, monkeypatch, site_ids=None):
    """Run one ingest per path in its own thread/session, all started together
    (a barrier inside the first host insert so every ingest has loaded its
    caches before any of them inserts)."""
    real = pp.insert_host_row
    barrier = threading.Barrier(len(paths), timeout=2)
    local = threading.local()

    def wrapper(*a, **kw):
        if not getattr(local, "waited", False):
            local.waited = True
            try:
                barrier.wait()
            except threading.BrokenBarrierError:
                pass   # serialised (PG advisory lock): the other is waiting for us
        return real(*a, **kw)
    monkeypatch.setattr(pp, "insert_host_row", wrapper)

    Session = sessionmaker(bind=eng, autoflush=False)
    results, errors = [None] * len(paths), []

    def work(i):
        s = Session()
        try:
            kw = {"site_id": site_ids[i]} if site_ids else {}
            results[i] = ingest_pcap(paths[i], s, **kw)
        except Exception as e:     # pragma: no cover - the failure being tested
            errors.append(e)
        finally:
            s.close()
    threads = [threading.Thread(target=work, args=(i,)) for i in range(len(paths))]
    for t in threads:
        t.start()
    for t in threads:
        t.join(120)
    assert not errors, errors
    return results


def test_pg_two_concurrent_ingests_same_site(pg, tmp_path, monkeypatch):
    path = _pcap(tmp_path, 300)
    r1, r2 = _concurrent_ingests(pg, [path, path], monkeypatch)
    with sessionmaker(bind=pg)() as s:
        _assert_no_duplicate_hosts(s)
        assert s.query(Host).count() == 301
        assert sorted([r1["hosts"], r2["hosts"]]) == [0, 301]
        # serialised: the second ingest reused the first one's sessions too
        assert s.query(NetworkSession).count() == 300
        assert sum(x.packet_count for x in s.query(NetworkSession)) == 600


def test_pg_concurrent_ingests_keep_identity_merges(pg, tmp_path, monkeypatch):
    """Same IPs re-seen with NEW MACs (renumbering / IP conflict) in a
    concurrent upload give exactly the result of sequential uploads: the
    second ingest's host_identity reconciliation sees the first one's rows."""
    a = _pcap(tmp_path, 50, name="a.pcap")
    b = tmp_path / "b.pcap"
    wrpcap(str(b), [_pkt(i, mac="06:00:00:00:00:%02x" % i) for i in range(50)])
    _concurrent_ingests(pg, [a, str(b)], monkeypatch)
    with sessionmaker(bind=pg)() as s:
        concurrent = _identities(s)
        _assert_no_duplicate_hosts(s)
    # reference: sequential, in both orders (which upload wins the lock varies)
    refs = []
    for order in ((a, str(b)), (str(b), a)):
        Base.metadata.drop_all(pg)
        Base.metadata.create_all(pg)
        with sessionmaker(bind=pg, autoflush=False)() as s:
            get_default_site(s)
            s.commit()
            for p in order:
                ingest_pcap(p, s)
            refs.append(_identities(s))
    assert concurrent in refs


def test_pg_concurrent_ingests_different_sites_run_in_parallel(pg, tmp_path, monkeypatch):
    with sessionmaker(bind=pg)() as s:
        other = Site(name="Plant B", code="plant-b", created_at=T0.replace(tzinfo=None))
        s.add(other)
        s.commit()
        sids = [get_default_site(s).id, other.id]
    path = _pcap(tmp_path, 100)
    r = _concurrent_ingests(pg, [path, path], monkeypatch, site_ids=sids)
    assert [x["hosts"] for x in r] == [101, 101]
    with sessionmaker(bind=pg)() as s:
        _assert_no_duplicate_hosts(s)
        assert {sid: s.query(Host).filter(Host.site_id == sid).count() for sid in sids} == \
            {sids[0]: 101, sids[1]: 101}


def test_sqlite_two_threads_file_db(tmp_path, monkeypatch):
    """SQLite file DB, write sessions (BEGIN IMMEDIATE, as the ingest routes
    use): two concurrent ingests of the same capture both succeed."""
    from app.db import write_engine
    eng = make_engine(f"sqlite:///{tmp_path / 'two.db'}")
    Base.metadata.create_all(eng)
    with sessionmaker(bind=eng)() as s:
        get_default_site(s)
        s.commit()
    path = _pcap(tmp_path, 300)
    r1, r2 = _concurrent_ingests(write_engine(eng), [path, path], monkeypatch)
    with sessionmaker(bind=eng)() as s:
        _assert_no_duplicate_hosts(s)
        assert s.query(Host).count() == 301
        assert sorted([r1["hosts"], r2["hosts"]]) == [0, 301]
        assert s.query(NetworkSession).count() == 300
    eng.dispose()


def test_non_postgres_takes_no_ingest_lock(lite):
    with sessionmaker(bind=lite)() as s:
        pp._serialize_site_ingest(s)       # no-op, no SQL error


# ============================================= 1d. 5k new hosts stay fast ==

def test_5k_new_hosts_fast_path_timing(tmp_path):
    eng = make_engine(f"sqlite:///{tmp_path / 'perf.db'}")
    Base.metadata.create_all(eng)
    path = _pcap(tmp_path, 5000)
    s = sessionmaker(bind=eng, autoflush=False)()
    t = time.perf_counter()
    stats = ingest_pcap(path, s)
    elapsed = time.perf_counter() - t
    assert stats["hosts"] == 5001 and stats["host_insert_conflicts"] == 0
    assert s.query(Host).count() == 5001
    s.close()
    eng.dispose()
    print(f"\n5k-new-host ingest: {elapsed:.2f}s")
    assert elapsed < 20      # measured ~5.7s; generous bound for slow CI


# ============================================ 2. cross-FW dedup source_ref ==

@pytest.fixture
def db():
    eng = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    Base.metadata.create_all(eng)
    s = sessionmaker(bind=eng)()
    yield s
    s.close()


def _fw(db, name):
    fw = Firewall(name=name, vendor="cisco", is_multi_fw=True, topology_confirmed=False)
    db.add(fw)
    db.flush()
    return fw


def _iface(db, fw, name):
    i = FirewallInterface(firewall_id=fw.id, name=name, side="outside", is_ha=False, is_mgmt_only=False)
    db.add(i)
    db.flush()
    return i


def _rule(db, fw, action="permit", src="any", dst="any", port=None, proto=None, pid="1", vdom=None):
    r = FirewallRule(firewall_id=fw.id, device_type="cisco", action=action, src=src, dst=dst,
                     dst_port=port, protocol=proto, policy_id=pid, vdom=vdom, enabled=True)
    db.add(r)
    db.flush()
    return r


def _pair(db):
    a, b = _fw(db, "FW-A"), _fw(db, "FW-B")
    ia, ib = _iface(db, a, "wan1"), _iface(db, b, "wan1")
    ia.connects_to_interface_id, ib.connects_to_interface_id = ib.id, ia.id
    _rule(db, a, action="deny", pid="99")     # explicit denies: no missing-deny noise
    _rule(db, b, action="deny", pid="99")
    db.query(FirewallRule).filter(FirewallRule.policy_id == "99").update(
        {"src_zone": "wan1"}, synchronize_session="fetch")
    db.commit()
    return a, b


def _open(db, check):
    return (db.query(Finding).filter(Finding.check_name == check, Finding.status == "open")
            .order_by(Finding.id).all())


def test_any_any_same_policy_id_on_both_firewalls_distinct(db):
    a, b = _pair(db)
    ra, rb = _rule(db, a, pid="1"), _rule(db, b, pid="1")
    db.commit()
    run_cross_fw_checks(db)
    db.commit()
    rows = _open(db, "cross_fw_any_any_permit")
    assert len(rows) == 2
    assert {f.rule_id for f in rows} == {ra.id, rb.id}
    assert {f.device_name for f in rows} == {"FW-A", "FW-B"}
    refs = {f.source_ref for f in rows}
    assert refs == {f"cross_fw_any_any_permit:{a.id}>{b.id}:vd=-:rule=1",
                    f"cross_fw_any_any_permit:{b.id}>{a.id}:vd=-:rule=1"}

    # re-run: no duplicates, nothing closed
    out = run_cross_fw_checks(db)
    db.commit()
    assert out["auto_resolved"] == 0
    assert len(_open(db, "cross_fw_any_any_permit")) == 2
    assert db.query(Finding).filter(Finding.check_name == "cross_fw_any_any_permit").count() == 2

    # fix the condition on both firewalls -> both close
    ra.dst, rb.dst = "10.0.0.0/24", "10.0.0.0/24"
    db.commit()
    out = run_cross_fw_checks(db)
    db.commit()
    assert _open(db, "cross_fw_any_any_permit") == []
    closed = db.query(Finding).filter(Finding.check_name == "cross_fw_any_any_permit").all()
    assert len(closed) == 2 and all(f.status == "closed" for f in closed)


def test_any_any_fix_on_one_firewall_closes_only_its_finding(db):
    a, b = _pair(db)
    ra, _rb = _rule(db, a, pid="1"), _rule(db, b, pid="1")
    db.commit()
    run_cross_fw_checks(db)
    ra.action = "deny"
    db.commit()
    run_cross_fw_checks(db)
    db.commit()
    (left,) = _open(db, "cross_fw_any_any_permit")
    assert left.device_name == "FW-B"


def test_any_any_same_policy_id_different_vdoms_distinct(db):
    a, b = _pair(db)
    _rule(db, a, pid="1", vdom="root")
    _rule(db, a, pid="1", vdom="ot")
    db.commit()
    run_cross_fw_checks(db)
    db.commit()
    refs = sorted(f.source_ref for f in _open(db, "cross_fw_any_any_permit"))
    assert refs == [f"cross_fw_any_any_permit:{a.id}>{b.id}:vd=ot:rule=1",
                    f"cross_fw_any_any_permit:{a.id}>{b.id}:vd=root:rule=1"]


def test_asymmetric_same_policy_id_on_both_firewalls_distinct(db):
    a, b = _pair(db)
    # A permits 10.1/24 -> 10.2/24 tcp/502, B permits 10.3/24 -> 10.4/24
    # tcp/502: each is asymmetric w.r.t. the other, both as policy 7.
    ra = _rule(db, a, src="10.1.0.0/24", dst="10.2.0.0/24", port="502", proto="tcp", pid="7")
    rb = _rule(db, b, src="10.3.0.0/24", dst="10.4.0.0/24", port="502", proto="tcp", pid="7")
    db.commit()
    run_cross_fw_checks(db)
    db.commit()
    rows = _open(db, "cross_fw_asymmetric_permit")
    assert len(rows) == 2 and {f.rule_id for f in rows} == {ra.id, rb.id}
    assert {f.source_ref for f in rows} == {
        f"cross_fw_asymmetric_permit:{a.id}>{b.id}:vd=-:rule=7:502:tcp",
        f"cross_fw_asymmetric_permit:{b.id}>{a.id}:vd=-:rule=7:502:tcp"}

    out = run_cross_fw_checks(db)
    db.commit()
    assert out["auto_resolved"] == 0 and out["findings_created"] == 0
    assert db.query(Finding).filter(Finding.check_name == "cross_fw_asymmetric_permit").count() == 2

    # fix: each side permits the other's flow -> both close
    _rule(db, a, src="10.3.0.0/24", dst="10.4.0.0/24", port="502", proto="tcp", pid="8")
    _rule(db, b, src="10.1.0.0/24", dst="10.2.0.0/24", port="502", proto="tcp", pid="8")
    db.commit()
    out = run_cross_fw_checks(db)
    db.commit()
    assert out["auto_resolved"] == 2
    assert _open(db, "cross_fw_asymmetric_permit") == []


def test_source_ref_stable_when_link_confirmed_from_other_side(db):
    a, b = _pair(db)
    _rule(db, a, pid="1")
    _rule(db, b, pid="1")
    db.commit()
    run_cross_fw_checks(db)
    db.commit()
    before = sorted(f.source_ref for f in db.query(Finding))
    # re-confirm the link with the interfaces' roles swapped
    ia, ib = sorted(db.query(FirewallInterface).all(), key=lambda i: i.id)
    ia.connects_to_interface_id = None
    db.commit()
    out = run_cross_fw_checks(db)
    db.commit()
    assert out["findings_created"] == 0 and out["auto_resolved"] == 0
    assert sorted(f.source_ref for f in db.query(Finding)) == before


def test_rule_reupload_keeps_finding(db):
    """The rule identifier is the policy id, not the row id: re-uploading
    the config (rules replaced, new ids) keeps the open finding."""
    a, b = _pair(db)
    r = _rule(db, a, pid="1")
    db.commit()
    run_cross_fw_checks(db)
    db.commit()
    db.delete(r)
    _rule(db, a, pid="1")
    db.commit()
    out = run_cross_fw_checks(db)
    db.commit()
    assert out["findings_created"] == 0 and out["auto_resolved"] == 0
    assert len(_open(db, "cross_fw_any_any_permit")) == 1


def test_long_rule_identifier_fits_source_ref(db):
    a, b = _pair(db)
    r = _rule(db, a, pid=None)
    r.raw_line = "access-list OUTSIDE extended permit ip any any " + "x" * 400
    db.commit()
    run_cross_fw_checks(db)
    db.commit()
    (f,) = _open(db, "cross_fw_any_any_permit")
    assert len(f.source_ref) <= 255 and ":sha1=" in f.source_ref
    out = run_cross_fw_checks(db)
    assert out["findings_created"] == 0 and out["auto_resolved"] == 0
