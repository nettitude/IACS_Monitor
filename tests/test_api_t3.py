"""
Tier-3 API / DB robustness (T3-01..T3-19, API side).

Every test uses a throw-away SQLite file under pytest's tmp dir, built with
app.db.make_engine (foreign_keys=ON, WAL, pysqlite BEGIN fix) - the same
settings the service uses.  The project's iasc_monitor.db is never touched.
"""
import io
import os
import socket
import subprocess
import sys
import threading
import time
from datetime import datetime
from pathlib import Path

import pytest
import sqlalchemy as sa
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

import app.main as main_mod
import app.api.routes as routes
from app.db import Base, get_db, make_engine, configure_sqlite_engine
from app.models import (
    Attestation, Finding, Firewall, FirewallInterface, FirewallRule,
    FortiAnalyzerEvent, Host, NetworkSession, PcapCapture, ProtocolDetail,
    SwitchInterface,
)

SAMPLES = Path(__file__).resolve().parent.parent / "sample_data"
PROJECT_ROOT = Path(__file__).resolve().parent.parent


# --------------------------------------------------------------- fixtures --

@pytest.fixture
def env(tmp_path, monkeypatch):
    engine = make_engine(f"sqlite:///{tmp_path / 't3.db'}")
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False)
    monkeypatch.setenv("IACS_REVIEW_ENABLED", "false")
    monkeypatch.setattr(main_mod, "init_db", lambda: None)

    def _get_db():
        s = Session()
        try:
            yield s
        except Exception:
            s.rollback()
            raise
        finally:
            s.close()

    main_mod.app.dependency_overrides[get_db] = _get_db
    yield engine, Session
    main_mod.app.dependency_overrides.pop(get_db, None)
    engine.dispose()


@pytest.fixture
def client(env):
    with TestClient(main_mod.app) as c:
        yield c


def _write_pcap(path: Path, n_packets: int, n_flows: int = 200) -> Path:
    """Modbus/TCP pcap built with scapy (templates written repeatedly)."""
    from scapy.all import Ether, IP, TCP, raw
    from scapy.utils import PcapWriter

    payload = b"\x00\x01\x00\x00\x00\x06\x01\x03\x00\x00\x00\x0a"
    tpl = [
        raw(Ether(src="00:11:22:33:44:%02x" % (i % 250), dst="00:11:22:33:55:01")
            / IP(src=f"10.0.{i // 250}.{i % 250 + 1}", dst="10.1.0.1")
            / TCP(sport=40000 + i, dport=502, flags="A") / payload)
        for i in range(n_flows)
    ]
    w = PcapWriter(str(path), linktype=1, sync=False)
    for n in range(n_packets):
        w.write(tpl[n % n_flows])
    w.close()
    return path


def _count(Session, model):
    with Session() as s:
        return s.query(model).count()


# ------------------------------------------------------------------ T3-01 --

def _free_port() -> int:
    with socket.socket() as so:
        so.bind(("127.0.0.1", 0))
        return so.getsockname()[1]


def test_health_stays_responsive_during_large_pcap_ingest(env, tmp_path):
    """A /health request must not wait for a running PCAP ingest (T3-01)."""
    import httpx
    import uvicorn

    # F-13 made the ingest ~5x faster: 15k packets over 200 flows now finish
    # before the probes below even start, so use 60k packets over 2000 flows
    # (~5 s of ingest work).
    pcap = _write_pcap(tmp_path / "big.pcap", 60_000, n_flows=2000)
    port = _free_port()
    server = uvicorn.Server(uvicorn.Config(main_mod.app, host="127.0.0.1", port=port,
                                           log_level="warning", lifespan="on"))
    st = threading.Thread(target=server.run, daemon=True)
    st.start()
    deadline = time.time() + 15
    while not server.started and time.time() < deadline:
        time.sleep(0.05)
    assert server.started
    base = f"http://127.0.0.1:{port}"
    result = {}

    def _upload():
        with httpx.Client(timeout=300) as c:
            result["resp"] = c.post(f"{base}/ingest/pcap", params={"site": "default"},
                                    files={"file": ("big.pcap", pcap.read_bytes())})
        result["done_at"] = time.time()

    try:
        up = threading.Thread(target=_upload)
        up.start()
        time.sleep(1.5)  # upload received, ingest under way
        latencies = []
        with httpx.Client(timeout=30) as c:
            for _ in range(5):
                t0 = time.time()
                assert c.get(f"{base}/health").json() == {"status": "ok"}
                latencies.append(time.time() - t0)
                time.sleep(0.2)
        health_done = time.time()
        up.join(300)
        assert result["resp"].status_code == 200, result["resp"].text
        # The ingest really was still running while /health answered.
        assert result["done_at"] > health_done, "ingest finished too fast to prove anything"
        assert max(latencies) < 1.0, latencies
        assert result["resp"].json()["stats"]["packets"] == 60_000
    finally:
        server.should_exit = True
        st.join(15)


# ------------------------------------------------------------------ T3-02 --

class _CountingUpload:
    """Minimal UploadFile stand-in that records how much was read."""

    def __init__(self, total: int, size=None):
        self.remaining = total
        self.read_bytes = 0
        self.size = size

    async def read(self, n=-1):
        n = self.remaining if n < 0 else min(n, self.remaining)
        self.remaining -= n
        self.read_bytes += n
        return b"x" * n


def test_spool_upload_aborts_at_first_chunk_over_limit():
    import anyio
    from fastapi import HTTPException

    up = _CountingUpload(total=50 * routes._UPLOAD_CHUNK)
    with pytest.raises(HTTPException) as ei:
        anyio.run(routes._read_limited, up, 2 * routes._UPLOAD_CHUNK, "Thing")
    assert ei.value.status_code == 413
    assert up.read_bytes <= 3 * routes._UPLOAD_CHUNK  # stopped early

    known = _CountingUpload(total=10_000, size=10_000)
    with pytest.raises(HTTPException):
        anyio.run(routes._read_limited, known, 100, "Thing")
    assert known.read_bytes == 0  # rejected from the declared size alone


def test_oversize_text_upload_413(client, monkeypatch):
    monkeypatch.setattr(routes, "_MAX_TEXT_BYTES", 1024)
    r = client.post("/ingest/arp", files={"file": ("a.txt", b"x" * 5000)})
    assert r.status_code == 413
    assert "1024" not in r.json()["detail"] or "MB" in r.json()["detail"]


def test_oversize_pcap_upload_413(client, monkeypatch):
    monkeypatch.setattr(routes, "_MAX_PCAP_BYTES", 1024)
    for path in ("/ingest/pcap", "/ingest/pcap-fw"):
        r = client.post(path, files={"file": ("a.pcap", b"\0" * 5000)})
        assert r.status_code == 413, (path, r.text)


def test_oversize_attestation_proof_413(client, env, monkeypatch):
    _, Session = env
    monkeypatch.setattr(routes, "_MAX_PROOF_BYTES", 1024)
    r = client.post("/attestation",
                    data={"checklist_id": "1.1", "attested_by": "a", "attested_at": "2026-09-01"},
                    files={"proof": ("p.pdf", b"%" * 5000, "application/pdf")})
    assert r.status_code == 413
    assert _count(Session, Attestation) == 0
    ok = client.post("/attestation",
                     data={"checklist_id": "1.1", "attested_by": "a", "attested_at": "2026-09-01"},
                     files={"proof": ("p.pdf", b"%" * 500, "application/pdf")})
    assert ok.status_code == 201 and ok.json()["has_proof"]


def test_body_size_middleware_rejects_declared_and_streamed():
    import anyio

    calls = []

    async def inner(scope, receive, send):
        from fastapi import HTTPException
        try:
            while True:
                m = await receive()
                if not m.get("more_body"):
                    break
        except HTTPException as exc:
            calls.append(exc.status_code)
            return
        calls.append("ok")

    mw = main_mod._BodySizeLimitMiddleware(inner, max_bytes=100)
    sent = []

    async def send(msg):
        sent.append(msg)

    async def run(headers, chunks):
        it = iter(chunks)

        async def receive():
            b = next(it)
            return {"type": "http.request", "body": b, "more_body": True}
        await mw({"type": "http", "method": "POST", "headers": headers}, receive, send)

    anyio.run(run, [(b"content-length", b"1000")], [b"x"])
    assert sent[0]["status"] == 413 and calls == []          # never reached the app
    anyio.run(run, [], [b"x" * 60, b"x" * 60, b""])
    assert calls == [413]                                     # chunked, counted


# ------------------------------------------------------------------ T3-03 --

def _seed_hosts_sessions(Session, n_hosts=12):
    with Session() as s:
        hosts = [Host(ip=f"10.9.0.{i + 1}", mac=f"00:00:00:00:01:{i:02x}") for i in range(n_hosts)]
        s.add_all(hosts)
        s.flush()
        for i in range(n_hosts - 1):
            sess = NetworkSession(src_host_id=hosts[i].id, dst_host_id=hosts[i + 1].id,
                                  src_port=1000 + i, dst_port=502, transport="tcp",
                                  protocol="modbus")
            s.add(sess)
            s.flush()
            for j in range(3):
                s.add(ProtocolDetail(session_id=sess.id, protocol="modbus", summary=f"f{j}"))
        for i in range(5):
            s.add(SwitchInterface(device_name="sw1", port_name=f"Gi0/{i}"))
            s.add(FirewallRule(device_type="cisco", device_name="acl", action="permit",
                               src="any", dst="any"))
        s.commit()
        return [h.id for h in hosts]


@pytest.mark.parametrize("path,total", [
    ("/hosts", 12), ("/assets", 12), ("/sessions", 11),
    ("/switch-interfaces", 5), ("/firewall-rules", 5),
])
def test_list_endpoints_paginate_with_total(client, env, path, total):
    _, Session = env
    _seed_hosts_sessions(Session)
    full = client.get(path)
    assert full.status_code == 200
    assert full.headers["X-Total-Count"] == str(total)
    assert len(full.json()) == total                       # default limit returns all
    ids = [r["id"] for r in full.json()]
    page = client.get(path, params={"limit": 2, "offset": 3})
    assert page.headers["X-Total-Count"] == str(total)
    assert [r["id"] for r in page.json()] == ids[3:5]
    for bad in ({"limit": 0}, {"limit": 10_001}, {"offset": -1}):
        assert client.get(path, params=bad).status_code == 422


def test_session_details_and_attestation_paginate(client, env):
    _, Session = env
    _seed_hosts_sessions(Session)
    with Session() as s:
        sid = s.query(NetworkSession.id).order_by(NetworkSession.id).first()[0]
    r = client.get(f"/sessions/{sid}/details", params={"limit": 2})
    assert r.headers["X-Total-Count"] == "3" and len(r.json()) == 2
    for i in range(3):
        client.post("/attestation", data={"checklist_id": f"1.{i + 1}", "attested_by": "x",
                                          "attested_at": "2026-09-01"})
    r = client.get("/attestation", params={"limit": 1, "offset": 1})
    assert r.headers["X-Total-Count"] == "3" and len(r.json()) == 1


def test_topology_bounds_and_edges_reference_returned_nodes(client, env):
    _, Session = env
    _seed_hosts_sessions(Session)
    d = client.get("/topology", params={"host_limit": 5}).json()
    node_ids = {n["id"] for n in d["nodes"]}
    assert len(node_ids) == 5
    assert d["edges"] and all(e["source"] in node_ids and e["target"] in node_ids
                              for e in d["edges"])
    assert d["truncated"] is True and d["hosts_total"] == 12
    full = client.get("/topology")
    assert full.json()["truncated"] is False and len(full.json()["edges"]) == 11
    assert full.headers["X-Hosts-Total"] == "12"
    for bad in ({"host_limit": 0}, {"host_limit": 10**7}, {"session_limit": 10**7}):
        assert client.get("/topology", params=bad).status_code == 422


# ------------------------------------------------------------ T3-04 / 05 --

def _export_ids(client, **params):
    r = client.get("/findings/export", params=params)
    assert r.status_code == 200, r.text
    text = r.content.decode("utf-8-sig")
    lines = [l for l in text.split("\r\n") if l]
    return sorted(int(l.split(",")[0]) for l in lines[1:])


def test_export_firewall_id_filter_in_sql_matches_int_and_str(client, env):
    _, Session = env
    with Session() as s:
        rows = [
            Finding(category="c", severity="low", title="int", detail={"firewall_id": 7}),
            Finding(category="c", severity="low", title="str", detail={"firewall_id": "7"}),
            Finding(category="c", severity="low", title="fw_id", detail={"fw_id": 7}),
            Finding(category="c", severity="low", title="other", detail={"firewall_id": 8}),
            Finding(category="c", severity="low", title="none", detail={}),
            Finding(category="c", severity="low", title="77", detail={"firewall_id": 77}),
        ]
        s.add_all(rows)
        s.commit()
        want = sorted(r.id for r in rows[:3])
        other = rows[3].id

    statements = []
    eng = env[0]

    def _capture(conn, cursor, statement, *a):
        statements.append(statement)
    sa.event.listen(eng, "before_cursor_execute", _capture)
    try:
        assert _export_ids(client, firewall_id="7") == want
    finally:
        sa.event.remove(eng, "before_cursor_execute", _capture)
    assert any("json_extract" in st.lower() for st in statements)   # filtered in SQL
    assert _export_ids(client, firewall_id="8") == [other]


def test_export_until_date_includes_that_whole_day(client, env):
    _, Session = env
    with Session() as s:
        a = Finding(category="c", severity="low", title="late on 30th",
                    created_at=datetime(2026, 9, 30, 23, 30))
        b = Finding(category="c", severity="low", title="1st",
                    created_at=datetime(2026, 10, 1, 0, 0, 1))
        c = Finding(category="c", severity="low", title="29th",
                    created_at=datetime(2026, 9, 29, 12, 0))
        s.add_all([a, b, c])
        s.commit()
        ids = (a.id, b.id, c.id)
    assert _export_ids(client, until="2026-09-30") == sorted([ids[0], ids[2]])
    assert _export_ids(client, until="2026-09-29") == [ids[2]]
    assert _export_ids(client, since="2026-09-30", until="2026-09-30") == [ids[0]]
    assert _export_ids(client, until="2026-09-30T12:00:00") == [ids[2]]
    assert client.get("/findings/export", params={"until": "nope"}).status_code == 400
    summ = client.get("/findings/export/summary", params={"status": "open", "until": "2026-09-30"})
    assert summ.status_code == 200


def test_export_streams_many_rows(client, env):
    _, Session = env
    with Session() as s:
        s.add_all([Finding(category="c", severity="low", title=f"t{i}") for i in range(1203)])
        s.commit()
    assert len(_export_ids(client)) == 1203


# ------------------------------------------------------------------ T3-06 --

def test_syslog_reupload_counts_duplicates_separately(client, env):
    _, Session = env
    data = (SAMPLES / "sample_forti_events.cef").read_bytes()
    first = client.post("/ingest/forti-syslog", files={"file": ("e.cef", data)}).json()["stats"]
    second = client.post("/ingest/forti-syslog", files={"file": ("e.cef", data)}).json()["stats"]
    assert "duplicates_skipped" in first and first["duplicates_skipped"] == 0
    if routes._ingest_syslog_line_ex is None:
        pytest.skip("forti_parser without ingest_syslog_line_ex")
    assert second["events_created"] == 0 and second["findings_created"] == 0
    assert second["duplicates_skipped"] == first["events_created"]
    assert second["parse_failures"] == first["parse_failures"]
    assert _count(Session, FortiAnalyzerEvent) == first["events_created"]


def test_forti_event_and_report_duplicates(client, env):
    payload = {"devname": "fw1", "type": "traffic", "srcip": "10.0.0.1",
               "dstip": "10.0.0.2", "dstport": 502, "action": "accept", "policyid": 3}
    a = client.post("/ingest/forti-event", json=payload).json()
    b = client.post("/ingest/forti-event", json=payload).json()
    assert a["duplicate"] is False
    if routes._ingest_forti_event_json_ex is not None:
        assert b["duplicate"] is True and b["event_id"] == a["event_id"]
        assert b["findings_created"] == 0
    data = (SAMPLES / "sample_forti_traffic.csv").read_bytes()
    r1 = client.post("/ingest/forti-report", files={"file": ("r.csv", data)}).json()
    r2 = client.post("/ingest/forti-report", files={"file": ("r.csv", data)}).json()
    assert "duplicates_skipped" in r1 and r1["events_imported"] > 0
    if routes._ingest_syslog_line_ex is not None:
        assert r2["events_imported"] == 0 and r2["findings_created"] == 0
        assert r2["duplicates_skipped"] == r1["events_imported"]


# ------------------------------------------------------------------ T3-08 --

def test_sqlite_pragmas_on_file_and_memory(tmp_path):
    eng = make_engine(f"sqlite:///{tmp_path / 'p.db'}")
    with eng.connect() as c:
        assert c.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1
        assert c.exec_driver_sql("PRAGMA journal_mode").scalar() == "wal"
    eng.dispose()
    mem = make_engine("sqlite://")
    with mem.connect() as c:
        assert c.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1
        assert c.exec_driver_sql("PRAGMA journal_mode").scalar() == "memory"
    # idempotent on an externally built engine
    ext = sa.create_engine(f"sqlite:///{tmp_path / 'e.db'}")
    configure_sqlite_engine(ext)
    configure_sqlite_engine(ext)
    with ext.connect() as c:
        assert c.exec_driver_sql("PRAGMA foreign_keys").scalar() == 1


def test_sqlite_savepoint_rollback_is_isolated(tmp_path):
    """pysqlite BEGIN fix: a failed savepoint rolls back only itself and a
    released savepoint does not commit the outer transaction."""
    eng = make_engine(f"sqlite:///{tmp_path / 's.db'}")
    Base.metadata.create_all(eng)
    S = sessionmaker(bind=eng)
    with S() as s:
        s.add(Host(ip="10.0.0.1"))
        s.flush()
        try:
            with s.begin_nested():
                s.add(Host(ip="10.0.0.1"))   # ix_host_ip_only violation
                s.flush()
        except sa.exc.IntegrityError:
            pass
        with s.begin_nested():
            s.add(Host(ip="10.0.0.2"))
        s.rollback()                          # outer rollback discards all
    with S() as s:
        assert s.query(Host).count() == 0


def test_foreign_keys_enforced(env):
    _, Session = env
    with Session() as s:
        s.add(ProtocolDetail(session_id=999_999, protocol="modbus"))
        with pytest.raises(sa.exc.IntegrityError):
            s.flush()


# ------------------------------------------------------------ T3-09 / 10 --

def test_new_indexes_and_unique_5tuple(env):
    engine, Session = env
    insp = sa.inspect(engine)
    names = {t: {i["name"]: i for i in insp.get_indexes(t)}
             for t in ("protocol_details", "network_sessions", "hosts")}
    assert "ix_protocol_details_session_id" in names["protocol_details"]
    assert "ix_network_sessions_dst_host_id" in names["network_sessions"]
    assert "ix_network_sessions_last_seen" in names["network_sessions"]
    assert "ix_hosts_last_seen" in names["hosts"]
    assert names["network_sessions"]["ux_session_5tuple"]["unique"]
    assert "ix_session_5tuple" not in names["network_sessions"]
    with Session() as s:
        a, b = Host(ip="1.1.1.1"), Host(ip="1.1.1.2")
        s.add_all([a, b])
        s.flush()
        kw = dict(src_host_id=a.id, dst_host_id=b.id, src_port=1, dst_port=502, transport="tcp")
        s.add(NetworkSession(**kw))
        s.flush()
        s.add(NetworkSession(**kw))
        with pytest.raises(sa.exc.IntegrityError):
            s.flush()


def test_same_pcap_twice_reuses_sessions(client, env, tmp_path):
    _, Session = env
    pcap = _write_pcap(tmp_path / "s.pcap", 300, n_flows=30)
    for _ in range(2):
        r = client.post("/ingest/pcap", files={"file": ("s.pcap", pcap.read_bytes())})
        assert r.status_code == 200, r.text
    assert _count(Session, NetworkSession) == 30


# ------------------------------------------------------------------ T3-11 --

def test_topology_firewalls_no_n_plus_one(client, env):
    engine, Session = env
    with Session() as s:
        for i in range(6):
            fw = Firewall(name=f"fw{i}", vendor="fortigate")
            s.add(fw)
            s.flush()
            for j in range(3):
                s.add(FirewallInterface(firewall_id=fw.id, name=f"port{j}"))
        s.commit()
    n = {"q": 0}

    def _count_q(*a):
        n["q"] += 1
    sa.event.listen(engine, "before_cursor_execute", _count_q)
    try:
        d = client.get("/topology/firewalls").json()
    finally:
        sa.event.remove(engine, "before_cursor_execute", _count_q)
    assert d["count"] == 6 and all(f["interface_count"] == 3 for f in d["firewalls"])
    assert n["q"] <= 4, n


# ------------------------------------------------------------------ T3-12 --

def test_unexpected_exception_text_not_leaked(client, monkeypatch, caplog):
    def boom(*a, **k):
        raise RuntimeError("SECRET /etc/internal path")
    monkeypatch.setattr(routes, "ingest_fortigate_config", boom)
    r = client.post("/ingest/fortigate-config", files={"file": ("f.txt", b"config x\nend\n")})
    assert r.status_code == 400
    detail = r.json()["detail"]
    assert "SECRET" not in detail and "error id" in detail
    err_id = detail.split("error id ")[1].split(";")[0]
    assert any(err_id in rec.getMessage() for rec in caplog.records)


def test_deliberate_validation_messages_kept(client):
    r = client.post("/ingest/mac-table", files={"file": ("m.txt", b"garbage\n")})
    assert r.status_code == 422 and "Could not detect MAC table format" in r.json()["detail"]
    r = client.post("/attestation", data={"checklist_id": "1.1", "attested_by": "a",
                                          "attested_at": "2026-09-01", "baseline_name": "nope"})
    assert r.status_code == 404 and r.json()["detail"] == "Baseline 'nope' not found"

    def bad(*a, **k):
        raise ValueError("No firewall policies found")
    import app.api.routes as R
    orig = R.ingest_fortigate_config
    R.ingest_fortigate_config = bad
    try:
        r = client.post("/ingest/fortigate-config", files={"file": ("f.txt", b"config x\nend\n")})
    finally:
        R.ingest_fortigate_config = orig
    assert r.status_code == 400 and r.json()["detail"] == "No firewall policies found"


# ------------------------------------------------------------------ T3-13 --

@pytest.mark.parametrize("path", ["/ingest/pcap", "/ingest/pcap-fw"])
@pytest.mark.parametrize("failing", ["classify_hosts", "check_unauthorized_industrial_writes"])
def test_pcap_failure_leaves_nothing_behind(client, env, tmp_path, monkeypatch, path, failing):
    _, Session = env
    pcap = _write_pcap(tmp_path / "f.pcap", 200, n_flows=10)

    def boom(*a, **k):
        raise RuntimeError("classification exploded")
    monkeypatch.setattr(routes, failing, boom)
    r = client.post(path, files={"file": ("f.pcap", pcap.read_bytes())})
    assert r.status_code == 400
    assert "exploded" not in r.json()["detail"]
    for model in (PcapCapture, Host, NetworkSession, ProtocolDetail):
        assert _count(Session, model) == 0, model.__name__


def test_pcap_fw_success_commits_capture(client, env, tmp_path):
    _, Session = env
    pcap = _write_pcap(tmp_path / "ok.pcap", 200, n_flows=10)
    r = client.post("/ingest/pcap-fw", files={"file": ("ok.pcap", pcap.read_bytes())})
    assert r.status_code == 200, r.text
    assert _count(Session, PcapCapture) == 1 and _count(Session, NetworkSession) == 10
    with Session() as s:
        assert {x.pcap_capture_id for x in s.query(NetworkSession)} == {r.json()["capture_id"]}


# ------------------------------------------------------------------ T3-14 --

def test_scheduler_lock_single_holder(tmp_path):
    lock = tmp_path / "sched.lock"
    first = main_mod._acquire_scheduler_lock(lock)
    second = main_mod._acquire_scheduler_lock(lock)
    try:
        assert first is not None
        assert second is None
        # another process on the same host cannot take it either
        code = (f"import sys; sys.path.insert(0, {str(PROJECT_ROOT)!r}); "
                f"import app.main as m; "
                f"print(m._acquire_scheduler_lock({str(lock)!r}) is None)")
        out = subprocess.run([sys.executable, "-c", code], capture_output=True, text=True,
                             env=dict(os.environ, IACS_DATABASE_URL=f"sqlite:///{tmp_path / 'x.db'}"))
        assert out.stdout.strip().endswith("True"), out.stderr
    finally:
        main_mod._release_scheduler_lock(first)
    again = main_mod._acquire_scheduler_lock(lock)
    assert again is not None
    main_mod._release_scheduler_lock(again)


def test_lifespan_starts_scheduler_only_with_lock(tmp_path, monkeypatch):
    monkeypatch.setattr(main_mod, "init_db", lambda: None)
    monkeypatch.setenv("IACS_REVIEW_ENABLED", "true")
    monkeypatch.setenv("IACS_SCHEDULER_LOCK", str(tmp_path / "l.lock"))
    held = main_mod._acquire_scheduler_lock()
    started = []
    import apscheduler.schedulers.background as bg
    monkeypatch.setattr(bg.BackgroundScheduler, "start", lambda self, *a, **k: started.append(1))
    try:
        with TestClient(main_mod.app):
            pass
        assert started == []           # lock held elsewhere -> no scheduler
    finally:
        main_mod._release_scheduler_lock(held)
    with TestClient(main_mod.app):
        pass
    assert started == [1]


# ------------------------------------------------------------------ T3-19 --

def test_rule_delete_sets_finding_rule_id_null(env):
    _, Session = env
    with Session() as s:
        rule = FirewallRule(device_type="fortigate", action="accept", firewall_id=None)
        s.add(rule)
        s.flush()
        f = Finding(category="config_review", severity="low", title="t", rule_id=rule.id)
        s.add(f)
        s.commit()
        s.query(FirewallRule).filter(FirewallRule.id == rule.id).delete(synchronize_session=False)
        s.commit()
        assert s.get(Finding, f.id).rule_id is None


def test_fortigate_config_reingest_with_foreign_keys(client, env):
    data = (SAMPLES / "sample_fortigate_config.txt").read_bytes()
    for _ in range(2):
        r = client.post("/ingest/fortigate-config",
                        params={"firewall_name": "FW1", "generate_findings": "true"},
                        files={"file": ("fg.txt", data)})
        assert r.status_code == 200, r.text


def test_export_columns_for_chain_style_evidence(client, env):
    """Access-path findings (chain / dead-end / upward skip) carry their
    context in detail.path / detail.chain / detail.service: the CSV fills the
    flat columns from them and never prints a Python list or dict."""
    import csv
    import io as _io
    from app.models import Finding
    _, Session = env
    with Session() as s:
        s.add(Finding(category="periodic_review", check_name="chain_ot_upward_skip", severity="medium",
                      title="OT upward skip", status="open", source_ref="t-chain",
                      detail={"path": {"src": {"level": 0, "zone": "port2", "scope": "10.60.1.30/32"},
                                       "dst": {"level": 5, "zone": "port1", "scope": "any"}},
                              "chain": [{"firewall_name": "FG-A", "policy_id": "7"},
                                        {"firewall_name": "FG-B", "policy_id": "9"}],
                              "service": ["tcp/443", "udp/53"]}))
        s.commit()
    r = client.get("/findings/export")
    row = [x for x in csv.DictReader(_io.StringIO(r.content.decode("utf-8-sig")))
           if x["check_name"] == "chain_ot_upward_skip"][0]
    assert row["firewall_name"] == "FG-A + FG-B" and row["policy_id"] == "FG-A#7 + FG-B#9"
    assert (row["src_ip"], row["dst_ip"]) == ("10.60.1.30/32", "any")
    assert (row["purdue_src"], row["purdue_dst"]) == ("0", "5")
    assert (row["source_zone"], row["dest_zone"]) == ("port2", "port1")
    assert row["protocol"] == "tcp/443, udp/53" and "[" not in row["protocol"]
