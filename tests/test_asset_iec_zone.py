"""
Asset Inventory IEC 62443 zone (owner, 2026-10-13: "asset inventory needs a zone
parameter" -> "IEC 62443 zone").

GET /assets rows carry ``iec_zones`` ([{id, name, sl_t, basis}]) and ``iec_zone``
(first name); PATCH /assets/{id}?iec_zone=<name> makes the host a host member of
that zone (created when missing), leaving any zone it was a host member of;
iec_zone= (empty) removes its own membership - a zone inherited from a subnet
member stays.  The CSV export has a ``zone`` column (the import maps it back).
"""
import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.main as main_mod
from app.db import Base, get_db
from app.models import Host, IecZone, IecZoneMember, Site


@pytest.fixture
def api(tmp_path, monkeypatch):
    engine = create_engine(f"sqlite:///{tmp_path / 'az.db'}", connect_args={"check_same_thread": False})
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
    s = Session()
    site = Site(name="Z", code="z")
    s.add(site)
    s.flush()
    s.add_all([Host(site_id=site.id, ip="10.10.1.10", mac="00:11:22:33:44:55"),
               Host(site_id=site.id, ip="10.10.2.10", mac="00:11:22:33:44:66"),
               Host(site_id=site.id, ip="10.40.1.5")])
    z = IecZone(site_id=site.id, name="Control L2", sl_t=2)
    s.add(z)
    s.flush()
    s.add(IecZoneMember(site_id=site.id, zone_id=z.id, kind="subnet", ref="10.10.2.0/24"))
    s.commit()
    sid = site.id
    s.close()
    with TestClient(main_mod.app) as c:
        yield c, sid, Session
    main_mod.app.dependency_overrides.pop(get_db, None)
    engine.dispose()


def _rows(c, sid):
    return {r["ip"]: r for r in c.get("/assets", params={"site_id": sid}).json()}


def test_rows_carry_zone_and_basis(api):
    c, sid, _ = api
    r = _rows(c, sid)
    assert r["10.10.2.10"]["iec_zone"] == "Control L2"
    (z,) = r["10.10.2.10"]["iec_zones"]
    assert z["sl_t"] == 2 and "subnet" in z["basis"]
    assert r["10.10.1.10"]["iec_zone"] is None and r["10.10.1.10"]["iec_zones"] == []


def test_set_zone_creates_it_and_moves_the_host(api):
    c, sid, Session = api
    hid = _rows(c, sid)["10.10.1.10"]["id"]
    j = c.patch(f"/assets/{hid}", params={"iec_zone": "PLC Cell 1"}).json()
    assert j["iec_zone"] == "PLC Cell 1" and j["iec_zone_change"] == "created"
    j = c.patch(f"/assets/{hid}", params={"iec_zone": "PLC Cell 1"}).json()
    assert j["iec_zone_change"] == "already"
    # moving it to another zone leaves the first one (no multi-zone placement)
    j = c.patch(f"/assets/{hid}", params={"iec_zone": "Control L2"}).json()
    assert [z["name"] for z in j["iec_zones"]] == ["Control L2"] and j["iec_zone_change"] == "added"
    s = Session()
    refs = [(m.kind, m.ref) for m in s.query(IecZoneMember).filter(IecZoneMember.kind == "host")]
    assert refs == [("host", "mac:00:11:22:33:44:55")]
    s.close()


def test_host_member_overrides_and_clearing_falls_back_to_the_subnet_zone(api):
    c, sid, _ = api
    hid = _rows(c, sid)["10.10.2.10"]["id"]
    j = c.patch(f"/assets/{hid}", params={"iec_zone": "HMI Zone"}).json()
    assert j["iec_zone"] == "HMI Zone" and j["iec_zones"][0]["basis"].startswith("host member")
    j = c.patch(f"/assets/{hid}", params={"iec_zone": ""}).json()
    assert j["iec_zone_change"] == "removed" and j["iec_zone"] == "Control L2"


def test_mac_less_host_by_address(api):
    c, sid, _ = api
    hid = _rows(c, sid)["10.40.1.5"]["id"]
    j = c.patch(f"/assets/{hid}", params={"iec_zone": "Enterprise"}).json()
    assert j["iec_zone"] == "Enterprise"


def test_export_has_the_zone_column(api):
    c, sid, _ = api
    hid = _rows(c, sid)["10.10.1.10"]["id"]
    c.patch(f"/assets/{hid}", params={"iec_zone": "PLC Cell 1"})
    text = c.get("/assets/export", params={"site_id": sid}).content.decode("utf-8-sig")
    head, *lines = text.splitlines()
    cols = head.split(",")
    assert "zone" in cols
    rows = {l.split(",")[cols.index("ip")]: l.split(",")[cols.index("zone")] for l in lines}
    assert rows["10.10.1.10"] == "PLC Cell 1" and rows["10.10.2.10"] == "Control L2"


def test_no_zones_no_cost(api):
    c, sid, Session = api
    s = Session()
    s.query(IecZoneMember).delete()
    s.query(IecZone).delete()
    s.commit()
    s.close()
    assert all(r["iec_zones"] == [] and r["iec_zone"] is None for r in _rows(c, sid).values())
