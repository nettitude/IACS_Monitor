"""
API: F-14 delete endpoints (gated by IACS_ENABLE_DELETE), N-12 GET /findings?q=,
F-02 GET /reports/compliance.pdf.

Temp-file SQLite DB (FKs on, as in production) with get_db overridden and the
lifespan's init_db() disabled so the project DB is never touched.
"""
from datetime import datetime, timezone

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

import app.main as main_mod
from app.db import Base, get_db, make_engine
from app.models import (
    ApprovedCommsEntry, ApprovedHost, Attestation, Baseline, Finding, FirewallDevice,
    FirewallRule, Host, NatRule, NetworkSession, ProtocolDetail,
)


@pytest.fixture
def Session(tmp_path):
    eng = make_engine(f"sqlite:///{tmp_path / 'misc.db'}")
    Base.metadata.create_all(eng)
    S = sessionmaker(bind=eng, autoflush=False)
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


@pytest.fixture
def enabled(monkeypatch):
    monkeypatch.setenv("IACS_ENABLE_DELETE", "true")


def _finding(s, **kw):
    base = dict(category="periodic_review", check_name="shadow_rule", severity="medium",
                status="open", title="t", isa62443_sr="SR 7.6", checklist_id="3.9",
                device_name="FW1", detail={})
    base.update(kw)
    f = Finding(**base)
    s.add(f)
    s.flush()
    return f


# ------------------------------------------------------------------ disabled

@pytest.mark.parametrize("path", ["/findings/1", "/attestation/1", "/firewall-devices/1",
                                  "/baselines/B1", "/hosts/1"])
def test_deletes_disabled_by_default(client, Session, path, monkeypatch):
    monkeypatch.delenv("IACS_ENABLE_DELETE", raising=False)
    with Session() as s:
        _finding(s)
        s.commit()
    r = client.delete(path)
    assert r.status_code == 403
    assert "IACS_ENABLE_DELETE" in r.json()["detail"]
    with Session() as s:
        assert s.query(Finding).count() == 1


def test_delete_flag_false_still_disabled(client, Session, monkeypatch):
    monkeypatch.setenv("IACS_ENABLE_DELETE", "false")
    assert client.delete("/findings/1").status_code == 403


# ------------------------------------------------------------------ enabled

def test_delete_finding(client, Session, enabled):
    with Session() as s:
        fid = _finding(s, title="gone").id
        keep = _finding(s, title="keep").id
        s.commit()
    r = client.delete(f"/findings/{fid}")
    assert r.status_code == 200 and r.json()["finding"]["title"] == "gone"
    assert client.delete(f"/findings/{fid}").status_code == 404
    with Session() as s:
        assert [f.id for f in s.query(Finding)] == [keep]


def test_delete_current_attestation_promotes_previous(client, Session, enabled):
    with Session() as s:
        old = Attestation(checklist_id="1.1", attested_by="a", is_current=False,
                          attested_at=datetime(2026, 1, 1, tzinfo=timezone.utc))
        cur = Attestation(checklist_id="1.1", attested_by="b", is_current=True,
                          attested_at=datetime(2026, 6, 1, tzinfo=timezone.utc))
        s.add_all([old, cur])
        s.commit()
        old_id, cur_id = old.id, cur.id
    r = client.delete(f"/attestation/{cur_id}")
    assert r.status_code == 200 and r.json()["promoted_current_id"] == old_id
    with Session() as s:
        rows = s.query(Attestation).all()
        assert [(a.id, a.is_current) for a in rows] == [(old_id, True)]
    assert client.delete("/attestation/999").status_code == 404


def test_delete_firewall_device_cascades(client, Session, enabled):
    with Session() as s:
        dev = FirewallDevice(name="FW-A")
        other = FirewallDevice(name="FW-B")
        s.add_all([dev, other])
        s.flush()
        r1 = FirewallRule(device_type="fortigate", firewall_device_id=dev.id, action="permit")
        r2 = FirewallRule(device_type="fortigate", firewall_device_id=dev.id, action="deny", enabled=False)
        r3 = FirewallRule(device_type="fortigate", firewall_device_id=other.id, action="permit")
        s.add_all([r1, r2, r3])
        s.flush()
        s.add_all([NatRule(firewall_device_id=dev.id, nat_type="dnat"),
                   NatRule(firewall_device_id=other.id, nat_type="snat")])
        f = _finding(s, rule_id=r1.id)
        s.commit()
        dev_id, fid, r3_id = dev.id, f.id, r3.id
    r = client.delete(f"/firewall-devices/{dev_id}")
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["firewall_rules"] == 2 and body["nat_rules"] == 1 and body["findings_unlinked"] == 1
    with Session() as s:
        assert s.get(FirewallDevice, dev_id) is None
        assert [x.id for x in s.query(FirewallRule)] == [r3_id]
        assert s.query(NatRule).count() == 1
        f = s.get(Finding, fid)
        assert f is not None and f.rule_id is None          # finding kept, unlinked
    assert client.delete(f"/firewall-devices/{dev_id}").status_code == 404


def test_delete_baseline_active_and_force(client, Session, enabled):
    with Session() as s:
        act = Baseline(name="ACT", is_active=True)
        old = Baseline(name="OLD", is_active=False)
        s.add_all([act, old])
        s.flush()
        for b in (act, old):
            s.add(ApprovedCommsEntry(baseline_id=b.id, src="10.0.0.1", dst="10.0.0.2", protocol="tcp"))
            s.add(ApprovedHost(baseline_id=b.id, ip="10.0.0.1", role="hmi"))
        s.add(Attestation(checklist_id="1.1", attested_by="x", baseline_id=old.id,
                          attested_at=datetime(2026, 1, 1, tzinfo=timezone.utc)))
        s.commit()
    r = client.delete("/baselines/ACT")
    assert r.status_code == 409 and "active" in r.json()["detail"]
    r = client.delete("/baselines/OLD")
    assert r.status_code == 409 and "attestation" in r.json()["detail"]
    r = client.delete("/baselines/OLD", params={"force": "true"})
    assert r.status_code == 200
    assert r.json()["approved_comms"] == 1 and r.json()["attestations"] == 1
    r = client.delete("/baselines/ACT", params={"force": "true"})
    assert r.status_code == 200 and r.json()["was_active"] is True
    with Session() as s:
        assert s.query(Baseline).count() == 0
        assert s.query(ApprovedCommsEntry).count() == 0
        assert s.query(ApprovedHost).count() == 0
        assert s.query(Attestation).count() == 0
    assert client.delete("/baselines/ACT").status_code == 404


def test_delete_host_referenced_and_force(client, Session, enabled):
    with Session() as s:
        a, b, c = Host(ip="10.0.0.1"), Host(ip="10.0.0.2"), Host(ip="10.0.0.3")
        s.add_all([a, b, c])
        s.flush()
        sess = NetworkSession(src_host_id=a.id, dst_host_id=b.id, protocol="modbus",
                              transport="tcp", src_port=1000, dst_port=502)
        keep = NetworkSession(src_host_id=b.id, dst_host_id=c.id, protocol="modbus",
                              transport="tcp", src_port=1001, dst_port=502)
        s.add_all([sess, keep])
        s.flush()
        s.add(ProtocolDetail(session_id=sess.id, protocol="modbus"))
        f = _finding(s, session_id=sess.id)
        s.commit()
        a_id, c_id, fid, keep_id = a.id, c.id, f.id, keep.id
    r = client.delete(f"/hosts/{a_id}")
    assert r.status_code == 409 and "force=true" in r.json()["detail"]
    r = client.delete(f"/hosts/{a_id}", params={"force": "true"})
    assert r.status_code == 200, r.text
    assert r.json()["sessions"] == 1 and r.json()["protocol_details"] == 1
    with Session() as s:
        assert s.get(Host, a_id) is None
        assert [x.id for x in s.query(NetworkSession)] == [keep_id]
        assert s.query(ProtocolDetail).count() == 0
        assert s.get(Finding, fid).session_id is None
    # c is referenced by `keep` too; a host with no sessions deletes without force
    with Session() as s:
        lone = Host(ip="10.9.9.9")
        s.add(lone)
        s.commit()
        lone_id = lone.id
    assert client.delete(f"/hosts/{lone_id}").status_code == 200
    assert client.delete(f"/hosts/{c_id}").status_code == 409


# ------------------------------------------------------------------ N-12 search

def test_findings_text_search(client, Session):
    with Session() as s:
        _finding(s, title="Telnet allowed to PLC", check_name="cleartext_protocol", isa62443_sr="SR 7.7",
                 checklist_id="3.5", device_name="FW-OT", severity="high")
        _finding(s, title="Shadowed rule 42", check_name="shadow_rule", device_name="Edge_FW")
        _finding(s, title="100% match _x_", check_name="other", device_name="FW-OT", status="closed")
        s.commit()

    def get(**params):
        r = client.get("/findings", params=params)
        assert r.status_code == 200
        return r.json(), int(r.headers["x-total-count"])

    rows, total = get(q="telnet")
    assert total == 1 and rows[0]["title"].startswith("Telnet")
    assert get(q="SHADOW_RULE")[1] == 1                 # check_name, case-insensitive
    assert get(q="sr 7.7")[1] == 1                      # isa62443_sr
    assert get(q="3.5")[1] == 1                         # checklist_id
    assert get(q="fw-ot")[1] == 2                       # device_name
    assert get(q="fw-ot", status="open")[1] == 1        # combines with filters
    assert get(q="fw-ot", severity="low")[1] == 0
    assert get(q="100%")[1] == 1                        # % is literal, not a wildcard
    assert get(q="%")[1] == 1
    assert get(q="_x_")[1] == 1                         # _ is literal
    assert get(q="t_l")[1] == 0                         # wildcard _ would match "Tel"
    assert get(q="   ")[1] == 3                         # blank q ignored
    rows, total = get(q="fw", limit=1)
    assert total == 3 and len(rows) == 1


# ------------------------------------------------------------------ F-02 route

def test_compliance_pdf_route(client, Session):
    with Session() as s:
        s.add(Baseline(name="B1", is_active=True))
        _finding(s, title="<b>markup</b> & stuff")
        s.commit()
    r = client.get("/reports/compliance.pdf", params={"site": "Plant <1>", "include_closed": "true"})
    assert r.status_code == 200
    assert r.headers["content-type"] == "application/pdf"
    assert "attachment" in r.headers["content-disposition"]
    assert r.content.startswith(b"%PDF")
    assert client.get("/reports/compliance.pdf", params={"baseline": "missing"}).status_code == 404
