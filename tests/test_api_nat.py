"""
API: GET /nat-rules (F-05) and the Purdue zone range check on
/ingest/fortigate-config (N-13).

Temp-file SQLite DB with get_db overridden and the lifespan's init_db()
disabled so the project DB is never touched.
"""
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from sqlalchemy.orm import sessionmaker

import app.main as main_mod
from app.db import Base, get_db, make_engine

SAMPLE = Path(__file__).resolve().parent.parent / "sample_data" / "sample_fortigate_config.txt"

# One VIP (dnat, port-forward) referenced by an inbound policy and one
# outbound policy with `set nat enable` (snat to the egress interface).
_NAT_CFG = """\
config system global
    set hostname "FW-NAT"
end
config system interface
    edit "wan1"
        set ip 203.0.113.1 255.255.255.0
    next
    edit "port2"
        set ip 10.0.1.1 255.255.255.0
    next
end
config firewall address
    edit "OT-NET"
        set subnet 10.0.1.0 255.255.255.0
    next
end
config firewall vip
    edit "VIP-HMI"
        set extip 203.0.113.10
        set extintf "wan1"
        set portforward enable
        set extport 8443
        set mappedport 443
        set mappedip "10.0.1.20"
    next
end
config firewall policy
    edit 10
        set name "in-hmi"
        set srcintf "wan1"
        set dstintf "port2"
        set srcaddr "all"
        set dstaddr "VIP-HMI"
        set action accept
        set service "HTTPS"
    next
    edit 20
        set name "out-nat"
        set srcintf "port2"
        set dstintf "wan1"
        set srcaddr "OT-NET"
        set dstaddr "all"
        set action accept
        set service "ALL"
        set nat enable
    next
end
"""


@pytest.fixture
def client(tmp_path, monkeypatch):
    eng = make_engine(f"sqlite:///{tmp_path / 'nat.db'}")
    Base.metadata.create_all(eng)
    S = sessionmaker(bind=eng, autoflush=False)
    monkeypatch.setattr(main_mod, "init_db", lambda: None)

    def _get_db():
        db = S()
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
    eng.dispose()


def _upload(client, text, name="fw.conf", **params):
    return client.post("/ingest/fortigate-config", params=params,
                       files={"file": (name, text.encode(), "text/plain")})


def test_nat_rules_empty(client):
    r = client.get("/nat-rules")
    assert r.status_code == 200
    assert r.json() == []
    assert r.headers["X-Total-Count"] == "0"


def test_nat_rules_from_sample_and_crafted_config(client):
    r = _upload(client, SAMPLE.read_text(), name=SAMPLE.name, firewall_name="FW-OT")
    assert r.status_code == 200, r.text
    sample_nat = r.json()["stats"]["nat_rules_created"]

    r = _upload(client, _NAT_CFG, firewall_name="FW-NAT")
    assert r.status_code == 200, r.text
    stats = r.json()["stats"]
    assert stats["nat_rules_created"] == 2

    r = client.get("/nat-rules")
    assert r.status_code == 200
    rows = r.json()
    assert int(r.headers["X-Total-Count"]) == len(rows) == sample_nat + 2
    expected_keys = {"id", "firewall_id", "firewall_device_id", "device_name", "device_type",
                     "nat_type", "name", "policy_id", "protocol", "src_intf", "orig_src",
                     "ext_ip", "ext_port", "mapped_ip", "mapped_port", "enabled",
                     "source_file", "raw", "site_id",  # site_id: multi-site phase 1
                     "nat_kind", "dst_intf", "orig_dst", "vdom",  # N-25 / N-24
                     "sequence", "nat_exempt"}  # B-13
    assert all(set(x) == expected_keys for x in rows)

    mine = [x for x in rows if x["firewall_id"] == stats["firewall_id"]]
    by = {x["nat_type"]: x for x in mine}
    assert set(by) == {"dnat", "snat"}
    d = by["dnat"]
    assert (d["name"], d["ext_ip"], d["ext_port"], d["mapped_ip"], d["mapped_port"],
            d["protocol"], d["policy_id"], d["enabled"]) == (
        "VIP-HMI", "203.0.113.10/32", "8443", "10.0.1.20/32", "443", "tcp", "10", True)
    s = by["snat"]
    assert (s["policy_id"], s["orig_src"], s["mapped_ip"]) == ("20", "10.0.1.0/24", "interface:wan1")
    assert d["device_type"] == "fortigate"


def test_nat_rules_filters_and_paging(client):
    _upload(client, SAMPLE.read_text(), name=SAMPLE.name, firewall_name="FW-OT")
    stats = _upload(client, _NAT_CFG, firewall_name="FW-NAT").json()["stats"]
    fw_id = stats["firewall_id"]

    rows = client.get("/nat-rules", params={"firewall_id": fw_id}).json()
    assert len(rows) == 2 and all(x["firewall_id"] == fw_id for x in rows)

    dev_id = rows[0]["firewall_device_id"]
    if dev_id is not None:
        by_dev = client.get("/nat-rules", params={"firewall_device_id": dev_id}).json()
        assert by_dev and all(x["firewall_device_id"] == dev_id for x in by_dev)
    assert client.get("/nat-rules", params={"firewall_device_id": 999999}).json() == []

    for nt in ("dnat", "snat", "DNAT"):
        r = client.get("/nat-rules", params={"firewall_id": fw_id, "nat_type": nt})
        assert r.status_code == 200
        assert [x["nat_type"] for x in r.json()] == [nt.lower()]
        assert r.headers["X-Total-Count"] == "1"

    r = client.get("/nat-rules", params={"limit": 1, "offset": 1})
    assert r.status_code == 200 and len(r.json()) == 1
    assert int(r.headers["X-Total-Count"]) >= 2


@pytest.mark.parametrize("bad", ["xnat", "masquerade", "1"])
def test_nat_rules_bad_type_422(client, bad):
    r = client.get("/nat-rules", params={"nat_type": bad})
    assert r.status_code == 422
    assert "nat_type" in r.json()["detail"]


def test_nat_rules_bad_paging_422(client):
    assert client.get("/nat-rules", params={"limit": 0}).status_code == 422
    assert client.get("/nat-rules", params={"offset": -1}).status_code == 422


@pytest.mark.parametrize("field,value", [
    ("purdue_zone_from", "6"), ("purdue_zone_to", "-1"),
    ("purdue_zone_from", "2.5"), ("purdue_zone_to", "abc"),
])
def test_fortigate_config_purdue_zone_range_422(client, field, value):
    params = {"purdue_zone_from": "4", "purdue_zone_to": "3", field: value}
    r = _upload(client, _NAT_CFG, firewall_name="FW-BAD", **params)
    assert r.status_code == 422, r.text
    detail = r.json()["detail"]
    assert field in detail and "Purdue level" in detail
    # same message as /ingest/firewall
    r2 = client.post("/ingest/firewall", params=params,
                     files={"file": ("acl.txt", b"access-list 101 permit ip any any\n", "text/plain")})
    assert r2.status_code == 422 and r2.json()["detail"] == detail
    # nothing was stored
    assert client.get("/firewall-devices").json() == []


def test_fortigate_config_purdue_zone_dmz_accepted(client):
    r = _upload(client, _NAT_CFG, firewall_name="FW-DMZ",
                purdue_zone_from="4", purdue_zone_to="L3.5")
    assert r.status_code == 200, r.text
    devs = [d for d in client.get("/firewall-devices").json() if d["name"] == "FW-DMZ"]
    assert devs and devs[0]["purdue_zone_from"] == 4 and devs[0]["purdue_zone_to"] == 3.5
