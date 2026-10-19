"""Regression tests: audit findings B-03, B-12, B-17, B-18, B-21, B-24."""
import io
import re
import time
from datetime import datetime, timedelta, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.main as main_mod
from app.api import routes
from app.db import Base, get_db
from app.models import Attestation, Host, Site
from app.parsers import mac_table_parser as mt
from app.parsers import switch_parser as sp
from app.site_devices import config_identity
from app.sites import find_site


@pytest.fixture
def session_factory(tmp_path):
    engine = create_engine(f"sqlite:///{tmp_path / 'qb.db'}",
                           connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False)
    with Session() as s:
        s.add_all([Site(name="Alpha", code="alpha"), Site(name="Beta", code="beta")])
        s.commit()
    yield Session
    engine.dispose()


@pytest.fixture
def client(session_factory, monkeypatch):
    monkeypatch.setenv("IACS_REVIEW_ENABLED", "false")
    monkeypatch.setattr(main_mod, "init_db", lambda: None)

    def _get_db():
        db = session_factory()
        try:
            yield db
        except Exception:
            db.rollback()
            raise
        finally:
            db.close()

    main_mod.app.dependency_overrides[get_db] = _get_db
    with TestClient(main_mod.app, raise_server_exceptions=False) as c:
        yield c
    main_mod.app.dependency_overrides.pop(get_db, None)


def _timed(fn, *a):
    t = time.perf_counter()
    out = fn(*a)
    return out, time.perf_counter() - t


# ------------------------------------------------------------------ B-03 --

_ADVERSARIAL = {
    "blank20k": "\n" * 20000,
    "blank_after_text": "x\n" + "\n" * 200000,
    "ws_lines": " \n" * 100000,
    "spaces200k": " " * 200000,
    "global_no_host": "config system global\n" * 10000,
    "vlan_blank": "vlan 1\n\n" * 20000,
}


@pytest.mark.parametrize("name", sorted(_ADVERSARIAL))
def test_regex_detectors_are_linear(name):
    text = _ADVERSARIAL[name]
    calls = [
        lambda: sp.detect_switch_vendor(text),
        lambda: sp.detect_switch_config_type(text, "hp"),
        lambda: sp.detect_switch_config_type(text, None),
        lambda: sp.check_vendor_hint(text, "cisco"),
        lambda: mt.detect_mac_table_type(text),
        lambda: mt.check_mac_vendor_hint(text, "hp"),
        lambda: config_identity(text, None),
    ]
    for c in calls:
        _, dt = _timed(c)
        assert dt < 0.5, (name, dt)


def test_config_identity_behaviour_preserved():
    forti = "#serial=FGT60ABCDEF123\nconfig system global\n    set hostname \"fw-1\"\nend\n"
    assert config_identity(forti, "fortigate") == ("fw-1", "FGT60ABCDEF123")
    assert config_identity("hostname edge1\n", "cisco_asa")[0] == "edge1"
    assert config_identity("  set deviceconfig system hostname pa1\n")[0] == "pa1"
    assert config_identity("config system global\nset foo\nend\n")[0] is None


def test_detectors_behaviour_preserved():
    assert sp.detect_switch_config_type("\n\n  vlan 10\n  untagged 1-4\n") == "hp_running_config"
    assert sp.detect_switch_config_type("  Local Port : 1\n", "hp") == "hp_lldp_detail"
    assert mt.detect_mac_table_type("  10  0011.2233.4455  DYNAMIC  Gi1/0/1  \r\n") == "cisco_mac_table"
    assert mt.detect_mac_table_type(" 001122-334455  1  10\n") == "hp_mac_table"


# ------------------------------------------------------------------ B-12 --

def _site_id(session_factory, code):
    with session_factory() as s:
        return s.query(Site).filter_by(code=code).one().id


def test_delete_attestation_promotes_only_same_site(client, session_factory, monkeypatch):
    monkeypatch.setenv("IACS_ENABLE_DELETE", "true")
    ids = {}
    for tag, code, who, day in (("a_old", "alpha", "old", "2026-08-01"),
                                ("a_cur", "alpha", "cur", "2026-09-01"),
                                ("b_cur", "beta", "b", "2026-09-02")):
        r = client.post("/attestation", data={"checklist_id": "1.1", "attested_by": who,
                                              "attested_at": day, "site": code})
        assert r.status_code == 201, r.text
        ids[tag] = r.json()["id"]
    r = client.delete(f"/attestation/{ids['a_cur']}")
    assert r.status_code == 200, r.text
    assert r.json()["promoted_current_id"] == ids["a_old"]
    with session_factory() as s:
        assert s.get(Attestation, ids["a_old"]).is_current is True
        assert s.get(Attestation, ids["b_cur"]).is_current is True  # untouched, still current
        assert s.query(Attestation).filter_by(site_id=_site_id(session_factory, "beta"),
                                              is_current=True).count() == 1


def test_delete_attestation_does_not_promote_other_site(client, session_factory, monkeypatch):
    monkeypatch.setenv("IACS_ENABLE_DELETE", "true")
    ra = client.post("/attestation", data={"checklist_id": "1.1", "attested_by": "a",
                                           "attested_at": "2026-09-01", "site": "alpha"}).json()
    rb = client.post("/attestation", data={"checklist_id": "1.1", "attested_by": "b",
                                           "attested_at": "2026-09-02", "site": "beta"}).json()
    # make Beta's row non-current to prove it is not promoted by an Alpha delete
    with session_factory() as s:
        s.get(Attestation, rb["id"]).is_current = False
        s.commit()
    r = client.delete(f"/attestation/{ra['id']}")
    assert r.status_code == 200 and r.json()["promoted_current_id"] is None
    with session_factory() as s:
        assert s.get(Attestation, rb["id"]).is_current is False


# ------------------------------------------------------------------ B-17 --

def _att(client, **kw):
    data = {"checklist_id": "1.1", "attested_by": "alice", "attested_at": "2026-09-01",
            "site": "alpha"}
    data.update(kw)
    return client.post("/attestation", data=data)


@pytest.mark.parametrize("who", ["", "   ", "\t"])
def test_attestation_blank_attested_by_rejected(client, who):
    assert _att(client, attested_by=who).status_code == 422


def test_attestation_future_date_rejected_today_allowed(client):
    assert _att(client, attested_at="2099-12-31").status_code == 422
    today = datetime.now(timezone.utc).date()
    assert _att(client, attested_at=(today + timedelta(days=2)).isoformat()).status_code == 422
    assert _att(client, attested_at=today.isoformat()).status_code == 201
    assert _att(client, attested_at="2020-01-01").status_code == 201
    assert _att(client, attested_at="not-a-date").status_code == 400


# ------------------------------------------------------------------ B-18 --

def test_csv_safe_helper():
    for bad in ("=HYPERLINK(\"http://x\",\"y\")", "=cmd|' /C calc'!A0", "+1", "-1+2", "@SUM(A1)",
                "\tfoo", "\rfoo"):
        assert routes._csv_safe(bad) == "'" + bad
    assert routes._csv_safe("plain") == "plain"
    assert routes._csv_safe("") == ""
    assert routes._csv_safe(None) is None
    assert routes._csv_safe(5) == 5
    assert routes._csv_safe(-5) == -5


def test_assets_export_escapes_formulas(client, session_factory):
    payload = "=HYPERLINK(\"http://evil\",\"x\")"
    with session_factory() as s:
        s.add(Host(ip="10.0.0.1", site_id=_site_id(session_factory, "alpha"),
                   hostname=payload, notes="=cmd|' /C calc'!A0", owner="+1+1"))
        s.commit()
    r = client.get("/assets/export")
    assert r.status_code == 200, r.text
    body = r.content.decode("utf-8-sig")
    assert "'=HYPERLINK" in body and "'=cmd|" in body and "'+1+1" in body
    assert not re.search(r'(^|,)"?=', body.replace("\r\n", "\n"), re.M)


def test_findings_exports_escape_formulas(client, session_factory):
    from app.models import Finding
    with session_factory() as s:
        s.add(Finding(category="x", check_name="=cmd|' /C calc'!A0", severity="high",
                      status="open", device_name="@x", checklist_id="=cmd|' /C calc'!A0",
                      isa62443_sr="@SUM(1)", title="=HYPERLINK(\"http://evil\")",
                      site_id=_site_id(session_factory, "alpha")))
        s.commit()
    for url in ("/findings/export", "/findings/export/summary"):
        r = client.get(url)
        assert r.status_code == 200, (url, r.text)
        body = r.content.decode("utf-8-sig")
        assert "'=cmd|" in body, url
        assert not re.search(r'(^|,)"?=', body.replace("\r\n", "\n"), re.M), url


# ------------------------------------------------------------------ B-21 --

def test_unmapped_purge_discard_gated(client, monkeypatch):
    monkeypatch.delenv("IACS_ENABLE_DELETE", raising=False)
    r1 = client.post("/site-devices/unmapped/purge")
    r2 = client.post("/site-devices/unmapped/discard", json={"device_key": "fw-x"})
    assert r1.status_code == 403 and r2.status_code == 403
    assert "IACS_ENABLE_DELETE" in r1.json()["detail"]
    monkeypatch.setenv("IACS_ENABLE_DELETE", "true")
    assert client.post("/site-devices/unmapped/purge").status_code == 200
    assert client.post("/site-devices/unmapped/discard", json={"device_key": "fw-x"}).status_code == 200


def test_mark_stale_requires_site_when_multiple(client, session_factory):
    old = datetime.now(timezone.utc) - timedelta(days=400)
    with session_factory() as s:
        s.add_all([Host(ip="10.0.0.1", site_id=_site_id(session_factory, "alpha"), last_seen=old),
                   Host(ip="10.0.0.2", site_id=_site_id(session_factory, "beta"), last_seen=old)])
        s.commit()
    assert client.post("/hosts/mark-stale", params={"older_than_days": 30}).status_code == 422
    aid = _site_id(session_factory, "alpha")
    r = client.post("/hosts/mark-stale", params={"older_than_days": 30, "site_id": aid})
    assert r.status_code == 200, r.text
    with session_factory() as s:
        stale = {h.ip: bool(h.stale) for h in s.query(Host)}
    assert stale == {"10.0.0.1": True, "10.0.0.2": False}


def test_mark_stale_single_site_auto(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'one.db'}",
                           connect_args={"check_same_thread": False})
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False)
    with Session() as s:
        s.add(Site(name="Only", code="only"))
        s.commit()
    monkeypatch.setenv("IACS_REVIEW_ENABLED", "false")
    monkeypatch.setattr(main_mod, "init_db", lambda: None)

    def _get_db():
        db = Session()
        try:
            yield db
        finally:
            db.close()

    main_mod.app.dependency_overrides[get_db] = _get_db
    try:
        with TestClient(main_mod.app) as c:
            assert c.post("/hosts/mark-stale", params={"older_than_days": 30}).status_code == 200
    finally:
        main_mod.app.dependency_overrides.pop(get_db, None)
        engine.dispose()


# ------------------------------------------------------------------ B-24 --

def test_superscript_site_value_no_500(client, session_factory):
    assert "²".isdigit()
    with session_factory() as s:
        assert find_site(s, "²") is None
        assert find_site(s, "١") is None
        assert find_site(s, str(_site_id(session_factory, "alpha"))).code == "alpha"
    r = client.post("/attestation", data={"checklist_id": "1.1", "attested_by": "a",
                                          "attested_at": "2026-09-01", "site": "²"})
    assert r.status_code == 422


def test_oversized_ids_not_500(client):
    big = "9" * 22
    for method, url, kw in (
        ("get", f"/hosts/{big}/history", {}),
        ("post", "/reviews/run", {"params": {"site_id": "9999999999999999999999"}}),
        ("get", "/assets", {"params": {"site_id": big}}),
        ("get", f"/findings/{big}", {}),
    ):
        r = getattr(client, method)(url, **kw)
        assert r.status_code in (404, 405, 422), (url, r.status_code, r.text)


def test_hostile_upload_filenames_not_500(client):
    pcap = b"\xd4\xc3\xb2\xa1\x02\x00\x04\x00" + b"\x00" * 16
    names = ["evil\x00.pcap", "a." + "x" * 300, "../../etc/passwd\x00.pcap", "z" * 400 + ".pcap", ""]
    for n in names:
        r = client.post("/ingest/pcap", params={"site": "alpha"}, files={"file": (n, io.BytesIO(pcap))})
        assert r.status_code < 500, (n[:20], r.status_code, r.text)
        r = client.post("/ingest/pcap-fw", params={"site": "alpha"}, files={"file": (n, io.BytesIO(pcap))})
        assert r.status_code < 500, (n[:20], r.status_code, r.text)


def test_clean_upload_name_and_suffix():
    assert "\x00" not in routes._clean_upload_name("a\x00b.pcap")
    assert routes._clean_upload_name("../../x/y.pcap") == "y.pcap"
    assert len(routes._clean_upload_name("q" * 500 + ".pcap")) <= 200
    assert routes._upload_suffix("a." + "x" * 300) == ".pcap"
    assert routes._upload_suffix("a\x00.pcapng") == ".pcapng"


def test_vendor_hint_case_insensitive():
    hp_cfg = "vlan 10\n untagged 1-4\n"
    cisco_cfg = "interface GigabitEthernet1/0/1\n switchport mode access\n"
    for hint in ("Cisco", " CISCO ", "cisco"):
        with pytest.raises(sp.VendorMismatchError):
            sp.check_vendor_hint(hp_cfg, hint)
    for hint in ("HP", "Hp"):
        with pytest.raises(sp.VendorMismatchError):
            sp.check_vendor_hint(cisco_cfg, hint)
    sp.check_vendor_hint(hp_cfg, "HP")
    with pytest.raises(sp.VendorMismatchError):
        mt.check_mac_vendor_hint(" 001122-334455  1  10\n", "Cisco")
    with pytest.raises(sp.VendorMismatchError):
        mt.check_mac_vendor_hint("10 0011.2233.4455 DYNAMIC Gi1/0/1\n", "HP")
