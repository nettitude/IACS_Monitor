"""
Audit batch C - DB-layer / ingest-robustness / API hardening regressions.

Covers:
  C-12  SQLite/PG pool-checkout TimeoutError -> 503 + Retry-After (never a
        500), and the QueuePool headroom / short checkout timeout in
        app.db.make_engine.
  C-13a Five CSV-upload routes return 422 (not 500) on unparseable input -
        random bytes and UTF-16/UTF-32 - and still 200 on valid UTF-8 CSV.
  C-13b POST /ingest/fortigate-config returns 422 and stores nothing when the
        body is not a FortiGate config ("hello world"); a valid minimal
        config still returns 200.
  C-16  The _RangeSafeRoute DataError mapping distinguishes a numeric
        overflow from a string-too-long, and the /assets routes cap every
        string parameter at its column width so an over-long value is a clean
        422, never a 500.

Temp-file SQLite DB (FKs on, as in production) with get_db overridden and the
lifespan's init_db() disabled so the operator DB is never touched.  The
Default site (code "default") is seeded so site-scoped routes resolve.
"""
import csv
import io

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.engine import make_url
from sqlalchemy.exc import TimeoutError as SATimeoutError
from sqlalchemy.orm import sessionmaker

import app.main as main_mod
import app.db as db_mod
from app.db import Base, get_db, make_engine


# --------------------------------------------------------------- fixtures --

@pytest.fixture
def Session(tmp_path):
    eng = make_engine(f"sqlite:///{tmp_path / 'dbapi.db'}")
    Base.metadata.create_all(eng)
    S = sessionmaker(bind=eng, autoflush=False)
    # Seed the Default site so ?site=default resolves.
    from app.sites import get_default_site
    with S() as s:
        get_default_site(s)
        s.commit()
    yield S
    eng.dispose()


@pytest.fixture
def client(Session, monkeypatch):
    monkeypatch.setattr(main_mod, "init_db", lambda: None)

    def _get_db():
        db = Session()
        try:
            yield db
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    main_mod.app.dependency_overrides[get_db] = _get_db
    with TestClient(main_mod.app) as c:
        yield c
    main_mod.app.dependency_overrides.pop(get_db, None)


def _csv_bytes(text: str) -> bytes:
    return text.encode("utf-8")


_GOOD_COMMS = "src,dst,dst_port\n10.0.0.1,10.0.0.2,502\n"
_GOOD_HOSTS = "ip,role\n10.0.0.5,jump_host\n"
_GOOD_ASSETS = "ip,mac\n10.0.0.9,\n"
_GOOD_POLICIES = "policy_id\n1\n"
_GOOD_REPORT = "srcip,dstip,action\n10.0.0.1,10.0.0.2,accept\n"

_CSV_ROUTES_GOOD = {
    "/ingest/baseline/comms-matrix": _GOOD_COMMS,
    "/ingest/baseline/approved-hosts": _GOOD_HOSTS,
    "/ingest/baseline/asset-inventory": _GOOD_ASSETS,
    "/ingest/baseline/reviewed-policies": _GOOD_POLICIES,
    "/ingest/forti-report": _GOOD_REPORT,
}


# ============================================================ C-13a CSV ==

@pytest.mark.parametrize("route", list(_CSV_ROUTES_GOOD))
def test_csv_route_random_bytes_is_422_not_500(client, route):
    """Random binary -> csv.Error deep in the parser used to 500; now 422."""
    blob = bytes(range(256)) * 4
    r = client.post(route, files={"file": ("x.csv", blob, "application/octet-stream")})
    assert r.status_code == 422, (route, r.status_code, r.text[:200])


@pytest.mark.parametrize("route", list(_CSV_ROUTES_GOOD))
def test_csv_route_utf16_is_422_not_500(client, route):
    """A UTF-16 export (BOM FF FE) is not the UTF-8 CSV the parser expects."""
    blob = _GOOD_COMMS.encode("utf-16")   # includes a UTF-16 BOM
    r = client.post(route, files={"file": ("x.csv", blob, "text/csv")})
    assert r.status_code == 422, (route, r.status_code, r.text[:200])
    assert "UTF-16" in r.json()["detail"] or "CSV" in r.json()["detail"]


@pytest.mark.parametrize("route", list(_CSV_ROUTES_GOOD))
def test_csv_route_utf32_is_422(client, route):
    blob = _GOOD_COMMS.encode("utf-32")   # includes a UTF-32 BOM
    r = client.post(route, files={"file": ("x.csv", blob, "text/csv")})
    assert r.status_code == 422, (route, r.status_code, r.text[:200])


@pytest.mark.parametrize("route,good", list(_CSV_ROUTES_GOOD.items()))
def test_csv_route_valid_utf8_still_ok(client, route, good):
    r = client.post(route, files={"file": ("x.csv", _csv_bytes(good), "text/csv")})
    assert r.status_code == 200, (route, r.status_code, r.text[:200])


def test_utf8_bom_csv_still_accepted(client):
    """A UTF-8 CSV with a BOM (EF BB BF) must NOT be rejected (C-13/C-20)."""
    blob = _GOOD_COMMS.encode("utf-8-sig")
    r = client.post("/ingest/baseline/comms-matrix",
                    files={"file": ("x.csv", blob, "text/csv")})
    assert r.status_code == 200, r.text[:200]
    assert r.json()["stats"]["entries_loaded"] == 1


def test_baseline_read_csv_raises_clear_error_on_binary():
    """Unit: the parser helper raises csv.Error with a clear message so the
    route can map it to 422 (random bytes decoded to text with embedded
    newlines)."""
    from app.parsers.baseline_parser import _read_csv
    garbage = bytes(range(256)).decode("utf-8", errors="replace") * 4
    with pytest.raises(csv.Error) as ei:
        _read_csv(garbage)
    assert "CSV" in str(ei.value)


# ============================================= C-13b fortigate-config ==

def test_fortigate_config_junk_is_422_and_stores_nothing(client):
    r = client.post("/ingest/fortigate-config",
                    files={"file": ("notes.txt", b"hello world", "text/plain")})
    assert r.status_code == 422, r.text[:200]
    # Nothing persisted: no device, no findings.
    assert client.get("/firewall-devices?site_id=1").json() == []
    assert client.get("/findings?site_id=1").json() == []


def test_fortigate_config_valid_minimal_is_200(client):
    cfg = (
        b"config system global\nset hostname MINI-FW\nend\n"
        b"config firewall policy\nedit 1\nset srcintf port1\nset dstintf port2\n"
        b"set action accept\nnext\nend\n"
    )
    r = client.post("/ingest/fortigate-config",
                    files={"file": ("mini.conf", cfg, "text/plain")})
    assert r.status_code == 200, r.text[:300]


# ===================================================== C-16 assets caps ==

def _seed_host(client):
    client.post("/ingest/baseline/asset-inventory",
                files={"file": ("a.csv", _csv_bytes("ip,mac\n10.9.9.9,\n"), "text/csv")})
    rows = [h for h in client.get("/assets?site_id=1").json() if h.get("ip") == "10.9.9.9"]
    assert rows, "seed host not created"
    return rows[0]["id"]


def test_patch_assets_overlong_location_is_422(client):
    hid = _seed_host(client)
    r = client.patch(f"/assets/{hid}", params={"location": "L" * 300})
    assert r.status_code == 422, r.text[:200]


@pytest.mark.parametrize("field,n", [
    ("model", 300), ("serial_number", 300), ("firmware_version", 300),
    ("building", 300), ("panel", 300), ("owner", 300),
    ("asset_tag", 300), ("approved_by", 300), ("last_reviewed_by", 300),
])
def test_patch_assets_overlong_string_fields_are_422(client, field, n):
    hid = _seed_host(client)
    r = client.patch(f"/assets/{hid}", params={field: "x" * n})
    assert r.status_code == 422, (field, r.status_code, r.text[:200])


def test_patch_assets_within_limits_is_200(client):
    hid = _seed_host(client)
    r = client.patch(f"/assets/{hid}", params={"location": "Plant-A", "model": "PLC-1"})
    assert r.status_code == 200, r.text[:200]
    assert r.json()["site"] == "Plant-A"


def test_patch_assets_notes_is_unbounded(client):
    """notes maps to a Text column, so a long note is allowed (no cap)."""
    hid = _seed_host(client)
    r = client.patch(f"/assets/{hid}", params={"notes": "n" * 5000})
    assert r.status_code == 200, r.text[:200]


def test_get_assets_overlong_location_filter_is_422(client):
    r = client.get("/assets", params={"location": "Z" * 300, "site_id": 1})
    assert r.status_code == 422, r.text[:200]


def test_export_assets_overlong_location_is_422(client):
    r = client.get("/assets/export", params={"location": "Z" * 300})
    assert r.status_code == 422, r.text[:200]


# ---------------- C-16 DataError mapping (numeric vs string overflow) ----

def test_numeric_overflow_maps_to_422_numeric(client):
    """A path id above the DB integer range -> 422 with the numeric message
    (OverflowError on SQLite / DataError 22003 on PG)."""
    r = client.patch(f"/assets/{10 ** 25}", params={"criticality": "high"})
    assert r.status_code == 422
    assert r.json()["detail"] == "a numeric value is out of range"


class _FakeOrig:
    def __init__(self, pgcode, msg):
        self.pgcode = pgcode
        self._msg = msg

    def __str__(self):
        return self._msg


class _FakeDataError(Exception):
    def __init__(self, orig):
        self.orig = orig
        super().__init__(str(orig))


def test_data_error_detail_distinguishes_string_from_numeric():
    """_data_error_detail must not label a string-truncation DataError as a
    numeric overflow (shapes taken from real psycopg2 errors: 22001
    StringDataRightTruncation 'value too long for type character varying(128)'
    vs 22003 NumericValueOutOfRange 'smallint out of range')."""
    from app.api.routes import _data_error_detail
    string_err = _FakeDataError(_FakeOrig("22001", "value too long for type character varying(128)"))
    numeric_err = _FakeDataError(_FakeOrig("22003", "smallint out of range"))
    assert _data_error_detail(string_err) == "a text value is too long for its column"
    assert _data_error_detail(numeric_err) == "a numeric value is out of range"
    # Message-only fallback (no pgcode, e.g. a non-PG backend).
    assert _data_error_detail(_FakeDataError(_FakeOrig("", "value too long"))) \
        == "a text value is too long for its column"
    assert _data_error_detail(_FakeDataError(_FakeOrig("", "integer out of range"))) \
        == "a numeric value is out of range"


# ========================================= C-12 pool timeout -> 503 ==

def test_pool_checkout_timeout_maps_to_503(Session, monkeypatch):
    """A pool-checkout TimeoutError (every connection held by queued writers)
    is transient and must become 503 + Retry-After, not a 500."""
    monkeypatch.setattr(main_mod, "init_db", lambda: None)

    class _BoomDB:
        def __getattr__(self, name):
            def boom(*a, **k):
                raise SATimeoutError(
                    "QueuePool limit of size 15 overflow 25 reached, "
                    "connection timed out, timeout 10.00")
            return boom

    def _boom_db():
        yield _BoomDB()

    main_mod.app.dependency_overrides[get_db] = _boom_db
    try:
        with TestClient(main_mod.app) as c:
            r = c.get("/assets", params={"site_id": 1})
    finally:
        main_mod.app.dependency_overrides.pop(get_db, None)

    assert r.status_code == 503, r.text[:200]
    assert r.headers.get("Retry-After")


# ========================================= C-12 engine pool config ==

def test_make_engine_sets_pool_headroom_for_file_sqlite(tmp_path):
    eng = make_engine(f"sqlite:///{tmp_path / 'p.db'}")
    try:
        assert eng.pool.size() == db_mod.db_pool_size()
        assert eng.pool._max_overflow == db_mod.db_max_overflow()
        assert eng.pool._timeout == db_mod.db_pool_timeout_s()
    finally:
        eng.dispose()


def test_pool_timeout_shorter_than_busy_timeout():
    """A reader starved of a pool connection must fail fast (503) rather than
    block for the full SQLite busy window (C-12)."""
    assert db_mod.db_pool_timeout_s() * 1000 < db_mod.sqlite_busy_timeout_ms()


def test_make_engine_skips_pool_kwargs_for_memory_sqlite():
    """In-memory SQLite uses a single-connection pool that rejects pool_size;
    make_engine must not pass it (engine builds without raising)."""
    eng = make_engine("sqlite://")   # :memory:
    try:
        assert make_url(str(eng.url)).get_backend_name() == "sqlite"
    finally:
        eng.dispose()
