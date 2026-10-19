"""
SL0 and conduit firewall rules (owner, 2026-10-13).

* Security levels are 0-4: "SL0 - No Requirements" ... "SL4 - Advanced Resources";
  0 is a real level, distinct from "not set".  An SL-T of 0 is never a target
  anything falls below; an SL-C / SL-A of 0 is below any SL-T of 1 or more.
* A documented conduit carries the firewall policy numbers that implement it
  (POST /iec-conduits/{id}/rules, or policy_ids when documenting it); each rule
  shows its source, destination, allow / deny and services, whether it connects
  the conduit's zones, and the policies found between the zones are marked
  attached / not attached.  Documentation only.
"""
import contextlib

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

import app.main as main_mod
from app.db import Base, get_db
from app.iec_zones import SL_LABELS, parse_sl, sl_a_status, sl_below
from app.models import IecConduitRule

CFG = """config system interface
    edit "port1"
        set ip 10.10.1.1 255.255.255.0
    next
    edit "port2"
        set ip 10.10.2.1 255.255.255.0
    next
    edit "port3"
        set ip 10.40.1.1 255.255.255.0
    next
end
config firewall address
    edit "PLC"
        set subnet 10.10.1.10 255.255.255.255
    next
    edit "HMI"
        set subnet 10.10.2.10 255.255.255.255
    next
    edit "IT"
        set subnet 10.40.1.50 255.255.255.255
    next
end
config firewall service custom
    edit "Modbus"
        set tcp-portrange 502
    next
end
config firewall policy
    edit 1
        set name "HMI-to-PLC"
        set srcintf "port2"
        set dstintf "port1"
        set srcaddr "HMI"
        set dstaddr "PLC"
        set service "Modbus"
        set action accept
    next
    edit 2
        set name "IT-to-HMI"
        set srcintf "port3"
        set dstintf "port2"
        set srcaddr "IT"
        set dstaddr "HMI"
        set service "HTTPS"
        set action accept
    next
    edit 3
        set name "Deny-IT-PLC"
        set srcintf "port3"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "all"
        set service "ALL"
        set action deny
    next
{EXTRA}end
"""
EXTRA4 = """    edit 4
        set name "PLC-to-HMI-alarms"
        set srcintf "port1"
        set dstintf "port2"
        set srcaddr "PLC"
        set dstaddr "HMI"
        set service "SNMP"
        set action accept
    next
"""


@contextlib.contextmanager
def api_ctx(tmp_path, monkeypatch):
    """The seeded API (also used by tests/test_cov_routes.py)."""
    engine = create_engine(f"sqlite:///{tmp_path / 'cr.db'}", connect_args={"check_same_thread": False})
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
    with TestClient(main_mod.app) as c:
        sid = c.post("/sites", json={"name": "C", "code": "c"}).json()["id"]
        r = c.post("/ingest/fortigate-config", params={"site": "c", "firewall_name": "FW-C"},
                   files={"file": ("fw.conf", CFG.replace("{EXTRA}", EXTRA4).encode())})
        assert r.status_code == 200, r.text
        q = {"site_id": sid}
        z1 = c.post("/iec-zones", params=q, json={"name": "Control", "sl_t": 2}).json()["zone"]["id"]
        z2 = c.post("/iec-zones", params=q, json={"name": "Supervisory", "sl_t": 0}).json()["zone"]["id"]
        c.post(f"/iec-zones/{z1}/members", params=q, json={"kind": "subnet", "ref": "10.10.1.0/24"})
        c.post(f"/iec-zones/{z2}/members", params=q, json={"kind": "subnet", "ref": "10.10.2.0/24"})
        try:
            yield c, sid, z1, z2, Session
        finally:
            main_mod.app.dependency_overrides.pop(get_db, None)
            engine.dispose()


@pytest.fixture
def api(tmp_path, monkeypatch):
    with api_ctx(tmp_path, monkeypatch) as x:
        yield x


# ------------------------------------------------------------------ SL0 --

def test_labels_and_parsing():
    assert SL_LABELS[0] == "SL0 - No Requirements" and SL_LABELS[4] == "SL4 - Advanced Resources"
    assert [parse_sl(v) for v in ("SL0", 0, "SL2 - Simple Intentional Means", "SL-C 3", "4")] == [0, 0, 2, 3, 4]


def test_below_semantics():
    assert sl_below(0, 1) and sl_below(1, 2)
    assert not sl_below(0, 0) and not sl_below(3, 0)          # SL-T 0: no requirement
    assert not sl_below(None, 2) and not sl_below(1, None)
    assert sl_a_status(0, 0) == "meets" and sl_a_status(0, 2) == "below"
    assert sl_a_status(None, 0) == "not_assessed" and sl_a_status(2, None) is None


def test_sl0_stored_and_kept_distinct_from_not_set(api):
    c, sid, z1, z2, _ = api
    q = {"site_id": sid}
    zones = {z["name"]: z for z in c.get("/iec-zones", params=q).json()["zones"]}
    assert zones["Supervisory"]["sl_t"] == 0 and zones["Control"]["sl_t"] == 2
    j = c.patch(f"/iec-zones/{z1}", params=q, json={"sl_a": "SL0 - No Requirements"}).json()["zone"]
    assert j["sl_a"] == 0
    zones = {z["name"]: z for z in c.get("/iec-zones", params=q).json()["zones"]}
    assert zones["Control"]["sl_a_status"] == "below"
    assert c.patch(f"/iec-zones/{z1}", params=q, json={"sl_t": 5}).status_code == 422
    cd = c.post("/iec-conduits", params=q, json={"zone_a_id": z1, "zone_b_id": z2, "sl_t": 0, "sl_a": 0}).json()["conduit"]
    assert (cd["sl_t"], cd["sl_a"]) == (0, 0)


def test_host_sl_c_zero(api):
    c, sid, z1, z2, _ = api
    hosts = c.get("/assets", params={"site_id": sid}).json()
    hmi = next(h for h in hosts if h["ip"] == "10.10.2.10") if any(h["ip"] == "10.10.2.10" for h in hosts) else None
    if hmi is None:
        pytest.skip("config upload created no host rows")
    assert c.patch(f"/assets/{hmi['id']}", params={"sl_c": "SL0 - No Requirements"}).json()["sl_c"] == 0


def test_zone_hosts_below_with_sl0(api, ):
    from app.iec_zones import sl_c_summary

    class H:
        def __init__(self, ip, slc):
            self.id, self.ip, self.sl_c = ip, ip, slc
    s = sl_c_summary([H("10.0.0.1", 0), H("10.0.0.2", None), H("10.0.0.3", 2)], 2)
    assert s["assessed"] == 2 and [b["ip"] for b in s["below_target"]] == ["10.0.0.1"] and s["min"] == 0
    assert sl_c_summary([H("10.0.0.1", 0)], 0)["below_target"] == []


# ------------------------------------------------------- conduit rules --

def _conduit(c, sid, z1, z2):
    view = c.get("/iec-conduits", params={"site_id": sid}).json()
    return view["conduits"][0]


def test_attach_rules_details_and_zone_check(api):
    c, sid, z1, z2, _ = api
    q = {"site_id": sid}
    cid = c.post("/iec-conduits", params=q, json={"zone_a_id": z1, "zone_b_id": z2, "name": "HMI-PLC",
                                                  "firewall": "FW-C", "policy_ids": "1"}).json()["conduit"]["id"]
    r = c.post(f"/iec-conduits/{cid}/rules", params=q, json={"firewall": "FW-C", "policy_ids": "2, 3, #1"})
    assert r.status_code == 201 and len(r.json()["rules"]) == 3
    cd = _conduit(c, sid, z1, z2)
    rules = {x["policy_id"]: x for x in cd["rules"]}
    assert set(rules) == {"1", "2", "3"}
    p1 = rules["1"]
    assert p1["action"] == "allow" and p1["found"] and p1["connects_zones"] is True
    assert p1["policy_name"] == "HMI-to-PLC" and "tcp/502" in p1["services"]
    assert p1["src_intf"] == ["port2"] and p1["dst_intf"] == ["port1"]
    assert rules["2"]["connects_zones"] is False                 # IT -> HMI: not Control <-> Supervisory
    assert rules["3"]["action"] == "deny" and rules["3"]["connects_zones"] is None
    assert any("#2: the policy does not connect" in n for n in cd["rule_notes"])
    # policy 4 (PLC -> HMI alarms) is found between the zones but not attached
    assert any("not attached" in n and "policy 4" in n for n in cd["rule_notes"])
    found = [p for d in ("a_to_b", "b_to_a") for p in cd[d]["policies"]]
    assert {p["policy_id"]: p["attached"] for p in found} == {"1": True, "4": False}


def test_validation_duplicates_and_detach(api):
    c, sid, z1, z2, Session = api
    q = {"site_id": sid}
    cid = c.post("/iec-conduits", params=q, json={"zone_a_id": z1, "zone_b_id": z2}).json()["conduit"]["id"]
    assert c.post(f"/iec-conduits/{cid}/rules", params=q, json={"firewall": "FW-X", "policy_ids": "1"}).status_code == 422
    r = c.post(f"/iec-conduits/{cid}/rules", params=q, json={"firewall": "FW-C", "policy_ids": [1, 99]})
    assert r.status_code == 422 and "99" in r.json()["detail"]
    a = c.post(f"/iec-conduits/{cid}/rules", params=q, json={"firewall": "fw-c", "policy_ids": [1]}).json()["rules"][0]
    b = c.post(f"/iec-conduits/{cid}/rules", params=q, json={"firewall": "FW-C", "policy_ids": "1"}).json()["rules"][0]
    assert a["id"] == b["id"]                                    # attaching twice is a no-op
    assert c.post("/iec-conduits", params=q, json={"zone_a_id": z1, "zone_b_id": z2, "policy_ids": "1"}).status_code == 422
    assert c.delete(f"/iec-conduits/{cid}/rules/{a['id']}", params=q).status_code == 200
    assert c.delete(f"/iec-conduits/{cid}/rules/{a['id']}", params=q).status_code == 404
    assert _conduit(c, sid, z1, z2)["rules"] == []


def test_rule_survives_reupload_and_flags_a_removed_policy(api):
    c, sid, z1, z2, _ = api
    q = {"site_id": sid}
    cid = c.post("/iec-conduits", params=q, json={"zone_a_id": z1, "zone_b_id": z2, "firewall": "FW-C",
                                                  "policy_ids": "1, 4"}).json()["conduit"]["id"]
    r = c.post("/ingest/fortigate-config", params={"site": "c", "firewall_name": "FW-C"},
               files={"file": ("fw.conf", CFG.replace("{EXTRA}", "").encode())})   # policy 4 removed
    assert r.status_code == 200
    rules = {x["policy_id"]: x for x in _conduit(c, sid, z1, z2)["rules"]}
    assert rules["1"]["found"] and not rules["4"]["found"]
    assert any("#4: the policy is not in the firewall's configuration" in n for n in _conduit(c, sid, z1, z2)["rule_notes"])
    assert cid


def test_deleting_the_conduit_removes_its_rules(api):
    c, sid, z1, z2, Session = api
    q = {"site_id": sid}
    cid = c.post("/iec-conduits", params=q, json={"zone_a_id": z1, "zone_b_id": z2, "firewall": "FW-C",
                                                  "policy_ids": "1"}).json()["conduit"]["id"]
    assert c.delete(f"/iec-conduits/{cid}", params=q).status_code == 200
    s = Session()
    assert s.query(IecConduitRule).count() == 0
    s.close()


def test_pdf_lists_the_conduit_rules(api):
    import io
    from pypdf import PdfReader
    c, sid, z1, z2, _ = api
    q = {"site_id": sid}
    c.post("/iec-conduits", params=q, json={"zone_a_id": z1, "zone_b_id": z2, "name": "HMI-PLC", "sl_a": 0,
                                           "firewall": "FW-C", "policy_ids": "1, 3"})
    r = c.get("/reports/compliance.pdf", params=q)
    assert r.status_code == 200
    text = " ".join(p.extract_text() or "" for p in PdfReader(io.BytesIO(r.content)).pages)
    text = " ".join(text.split())
    assert "rules: FW-C #1, FW-C #3 (deny)" in text
    assert "SL-A 0" in text                                     # SL0 printed, not "not assessed"


def test_firewall_name_is_matched_exactly_not_as_a_pattern(api):
    """Audit 2026-10-14: the firewall name is an exact, case-insensitive match - a LIKE
    pattern ('FW%', 'FW_C') must not attach rules to whatever firewall happens to match."""
    c, sid, z1, z2, _ = api
    q = {"site_id": sid}
    cid = c.post("/iec-conduits", params=q, json={"zone_a_id": z1, "zone_b_id": z2}).json()["conduit"]["id"]
    for bad in ("FW%", "FW_C", "F%"):
        assert c.post(f"/iec-conduits/{cid}/rules", params=q, json={"firewall": bad, "policy_ids": "1"}).status_code == 422, bad
    assert c.post(f"/iec-conduits/{cid}/rules", params=q, json={"firewall": "fw-c", "policy_ids": "1"}).status_code == 201
