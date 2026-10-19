"""
Tests for the multi-firewall config-ingest path in forti_config_parser.py
and the API endpoints that complete the topology workflow.

Coverage:
  - First config ingested: single-FW mode, is_multi_fw=False
  - Second config ingested: is_multi_fw=True set on ALL Firewall rows
  - Interface extraction from config system interface blocks
  - Rule extraction (permit / deny) and multi-FW detection
  - API layer: POST /ingest/fortigate sets topology_state in response
  - forti_config_parser.ingest_fortigate_config — stats dict shape
"""
import textwrap
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool
from fastapi.testclient import TestClient

from app.db import Base, get_db
from app.main import app
from app.models import Firewall, FirewallInterface, FirewallRule
from app.parsers.forti_config_parser import ingest_fortigate_config


# ─── minimal FortiGate config fixtures ───────────────────────────────────────

_CONFIG_FW1 = textwrap.dedent("""\
    config system global
        set hostname FW-Perimeter
    end
    config system interface
        edit "wan1"
            set mode static
            set ip 203.0.113.1 255.255.255.252
            set allowaccess ping https ssh
            set role wan
            set status up
        next
        edit "dmz"
            set mode static
            set ip 10.10.10.1 255.255.255.0
            set allowaccess ping
            set role lan
            set status up
        next
    end
    config firewall policy
        edit 1
            set name "allow-web-out"
            set srcintf "dmz"
            set dstintf "wan1"
            set action accept
            set srcaddr "all"
            set dstaddr "all"
            set service "HTTP" "HTTPS"
            set status enable
        next
        edit 2
            set name "deny-all"
            set srcintf "any"
            set dstintf "any"
            set action deny
            set srcaddr "all"
            set dstaddr "all"
            set service "ALL"
            set status enable
        next
    end
""")

_CONFIG_FW2 = textwrap.dedent("""\
    config system global
        set hostname FW-Core
    end
    config system interface
        edit "wan1"
            set mode static
            set ip 10.10.10.2 255.255.255.0
            set allowaccess ping
            set role wan
            set status up
        next
        edit "internal"
            set mode static
            set ip 192.168.1.1 255.255.255.0
            set allowaccess ping https
            set role lan
            set status up
        next
    end
    config firewall policy
        edit 1
            set name "allow-scada"
            set srcintf "internal"
            set dstintf "wan1"
            set action accept
            set srcaddr "all"
            set dstaddr "all"
            set service "ALL"
            set status enable
        next
    end
""")


# ─── fixtures ─────────────────────────────────────────────────────────────────

@pytest.fixture
def db():
    # StaticPool keeps a single in-memory SQLite connection alive for the
    # whole test, so that db.commit() in the parser does not close the
    # connection and lose the schema (SQLite :memory: gives each new
    # connection an empty database).
    engine = create_engine(
        "sqlite:///:memory:",
        connect_args={"check_same_thread": False},
        poolclass=StaticPool,
    )
    Base.metadata.create_all(engine)
    Session = sessionmaker(bind=engine)
    session = Session()
    yield session
    session.close()


@pytest.fixture
def client(db):
    """FastAPI test client wired to the in-memory DB."""
    def _override_get_db():
        try:
            yield db
        finally:
            pass  # session lifecycle managed by `db` fixture

    app.dependency_overrides[get_db] = _override_get_db
    with TestClient(app) as c:
        yield c
    app.dependency_overrides.clear()


# ─── direct parser tests ──────────────────────────────────────────────────────

def test_first_ingest_single_fw_mode(db):
    stats = ingest_fortigate_config(_CONFIG_FW1, db, firewall_name="FW-Perimeter")
    db.commit()
    assert stats["topology_state"] == "single"
    assert stats["is_multi_fw"] is False
    fw = db.query(Firewall).one()
    assert fw.is_multi_fw is False


def test_first_ingest_stats_shape(db):
    stats = ingest_fortigate_config(_CONFIG_FW1, db, firewall_name="FW-Perimeter")
    db.commit()
    for key in ("firewall_id", "interfaces_created", "rules_created",
                "topology_state", "is_multi_fw"):
        assert key in stats, f"Missing key: {key}"


def test_first_ingest_interfaces_created(db):
    stats = ingest_fortigate_config(_CONFIG_FW1, db, firewall_name="FW-Perimeter")
    db.commit()
    assert stats["interfaces_created"] == 2
    names = {i.name for i in db.query(FirewallInterface).all()}
    assert "wan1" in names
    assert "dmz" in names


def test_first_ingest_rules_created(db):
    ingest_fortigate_config(_CONFIG_FW1, db, firewall_name="FW-Perimeter")
    db.commit()
    rules = db.query(FirewallRule).all()
    # FW1 has policy 1 (allow-web-out, service HTTP+HTTPS → 2 rows) and
    # policy 2 (deny-all, service ALL → 1 row) = 3 rows total.
    # The parser emits one FirewallRule per (src × dst × service) combination.
    assert len(rules) == 3
    actions = {r.action for r in rules}
    assert "permit" in actions
    assert "deny" in actions


def test_interface_ip_cidr_parsed(db):
    ingest_fortigate_config(_CONFIG_FW1, db, firewall_name="FW-Perimeter")
    db.commit()
    wan1 = db.query(FirewallInterface).filter_by(name="wan1").first()
    assert wan1 is not None
    assert wan1.ip_cidr is not None
    assert "203.0.113.1" in wan1.ip_cidr


def test_interface_network_cidr_parsed(db):
    ingest_fortigate_config(_CONFIG_FW1, db, firewall_name="FW-Perimeter")
    db.commit()
    dmz = db.query(FirewallInterface).filter_by(name="dmz").first()
    assert dmz is not None
    assert dmz.network_cidr == "10.10.10.0/24"


def test_interface_role_preserved(db):
    ingest_fortigate_config(_CONFIG_FW1, db, firewall_name="FW-Perimeter")
    db.commit()
    wan1 = db.query(FirewallInterface).filter_by(name="wan1").first()
    assert wan1.role == "wan"
    dmz = db.query(FirewallInterface).filter_by(name="dmz").first()
    assert dmz.role == "lan"


# ─── multi-FW activation ──────────────────────────────────────────────────────

def test_second_ingest_activates_multi_fw(db):
    ingest_fortigate_config(_CONFIG_FW1, db, firewall_name="FW-Perimeter")
    db.commit()
    stats2 = ingest_fortigate_config(_CONFIG_FW2, db, firewall_name="FW-Core")
    db.commit()
    assert stats2["topology_state"] == "multi"
    assert stats2["is_multi_fw"] is True
    # ALL Firewall rows must have is_multi_fw=True
    all_fw = db.query(Firewall).all()
    assert len(all_fw) == 2
    assert all(fw.is_multi_fw is True for fw in all_fw)


def test_second_ingest_both_fw_rows_flagged(db):
    """is_multi_fw must be True on the FIRST firewall row, not just the second."""
    ingest_fortigate_config(_CONFIG_FW1, db, firewall_name="FW-Perimeter")
    db.commit()
    ingest_fortigate_config(_CONFIG_FW2, db, firewall_name="FW-Core")
    db.commit()
    fw1 = db.query(Firewall).filter_by(name="FW-Perimeter").one()
    fw2 = db.query(Firewall).filter_by(name="FW-Core").one()
    assert fw1.is_multi_fw is True
    assert fw2.is_multi_fw is True


def test_second_ingest_interfaces_belong_to_correct_fw(db):
    ingest_fortigate_config(_CONFIG_FW1, db, firewall_name="FW-Perimeter")
    db.commit()
    ingest_fortigate_config(_CONFIG_FW2, db, firewall_name="FW-Core")
    db.commit()
    fw1 = db.query(Firewall).filter_by(name="FW-Perimeter").one()
    fw2 = db.query(Firewall).filter_by(name="FW-Core").one()
    fw1_iface_names = {i.name for i in db.query(FirewallInterface).filter_by(firewall_id=fw1.id).all()}
    fw2_iface_names = {i.name for i in db.query(FirewallInterface).filter_by(firewall_id=fw2.id).all()}
    assert "wan1" in fw1_iface_names and "dmz" in fw1_iface_names
    assert "wan1" in fw2_iface_names and "internal" in fw2_iface_names
    # No cross-contamination
    assert "internal" not in fw1_iface_names
    assert "dmz" not in fw2_iface_names


def test_second_ingest_rules_belong_to_correct_fw(db):
    ingest_fortigate_config(_CONFIG_FW1, db, firewall_name="FW-Perimeter")
    db.commit()
    ingest_fortigate_config(_CONFIG_FW2, db, firewall_name="FW-Core")
    db.commit()
    fw1 = db.query(Firewall).filter_by(name="FW-Perimeter").one()
    fw2 = db.query(Firewall).filter_by(name="FW-Core").one()
    fw1_rules = db.query(FirewallRule).filter_by(firewall_id=fw1.id).count()
    fw2_rules = db.query(FirewallRule).filter_by(firewall_id=fw2.id).count()
    # FW1: policy 1 (HTTP+HTTPS = 2 service rows) + policy 2 (deny-all, 1 row) = 3
    assert fw1_rules == 3   # allow-web-out (×2 services) + deny-all
    assert fw2_rules == 1   # allow-scada (1 service)


def test_third_ingest_stays_multi_fw(db):
    """Adding a third FW keeps everyone in multi_fw mode."""
    _CONFIG_FW3 = textwrap.dedent("""\
        config system global
            set hostname FW-Cell
        end
        config system interface
            edit "uplink"
                set mode static
                set ip 192.168.1.2 255.255.255.0
                set status up
            next
        end
    """)
    ingest_fortigate_config(_CONFIG_FW1, db, firewall_name="FW-Perimeter")
    db.commit()
    ingest_fortigate_config(_CONFIG_FW2, db, firewall_name="FW-Core")
    db.commit()
    stats3 = ingest_fortigate_config(_CONFIG_FW3, db, firewall_name="FW-Cell")
    db.commit()
    assert stats3["topology_state"] == "multi"
    assert db.query(Firewall).count() == 3
    assert all(fw.is_multi_fw for fw in db.query(Firewall).all())


# ─── API layer: POST /ingest/fortigate ────────────────────────────────────────

def test_api_ingest_first_config_single(client):
    resp = client.post(
        "/ingest/fortigate-config",
        files={"file": ("fw1.conf", _CONFIG_FW1.encode(), "text/plain")},
        data={"firewall_name": "FW-Perimeter"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["topology_state"] == "single"


def test_api_ingest_second_config_multi(client, db):
    client.post(
        "/ingest/fortigate-config",
        files={"file": ("fw1.conf", _CONFIG_FW1.encode(), "text/plain")},
        data={"firewall_name": "FW-Perimeter"},
    )
    resp = client.post(
        "/ingest/fortigate-config",
        files={"file": ("fw2.conf", _CONFIG_FW2.encode(), "text/plain")},
        data={"firewall_name": "FW-Core"},
    )
    assert resp.status_code == 200
    data = resp.json()
    assert data["topology_state"] == "multi"
    assert data["is_multi_fw"] is True


def test_api_topology_state_shows_both_fw(client):
    # firewall_name is a query parameter on the endpoint — pass via params=
    client.post(
        "/ingest/fortigate-config",
        files={"file": ("fw1.conf", _CONFIG_FW1.encode(), "text/plain")},
        params={"firewall_name": "FW-Perimeter"},
    )
    client.post(
        "/ingest/fortigate-config",
        files={"file": ("fw2.conf", _CONFIG_FW2.encode(), "text/plain")},
        params={"firewall_name": "FW-Core"},
    )
    resp = client.get("/topology/state")
    assert resp.status_code == 200
    state = resp.json()
    assert state["firewall_count"] == 2
    assert state["is_multi_fw"] is True
    fw_names = {fw["name"] for fw in state["firewalls"]}
    assert "FW-Perimeter" in fw_names
    assert "FW-Core" in fw_names


def test_api_topology_state_has_proposals(client):
    """The overlapping 10.10.10.0/24 subnet between FW1-dmz and FW2-wan1
    should produce at least one pending proposal."""
    client.post(
        "/ingest/fortigate-config",
        files={"file": ("fw1.conf", _CONFIG_FW1.encode(), "text/plain")},
        data={"firewall_name": "FW-Perimeter"},
    )
    client.post(
        "/ingest/fortigate-config",
        files={"file": ("fw2.conf", _CONFIG_FW2.encode(), "text/plain")},
        data={"firewall_name": "FW-Core"},
    )
    resp = client.get("/topology/state")
    state = resp.json()
    proposals = state["pending_proposals"]
    assert len(proposals) >= 1
    assert proposals[0]["confidence"] in ("high", "medium", "low")


def test_api_confirm_link_then_run_checks(client):
    client.post(
        "/ingest/fortigate-config",
        files={"file": ("fw1.conf", _CONFIG_FW1.encode(), "text/plain")},
        data={"firewall_name": "FW-Perimeter"},
    )
    client.post(
        "/ingest/fortigate-config",
        files={"file": ("fw2.conf", _CONFIG_FW2.encode(), "text/plain")},
        data={"firewall_name": "FW-Core"},
    )
    state = client.get("/topology/state").json()
    # Pick the proposal and confirm it
    proposal = state["pending_proposals"][0]
    resp = client.post("/topology/confirm-link", json={
        "iface_a_id": proposal["iface_a_id"],
        "iface_b_id": proposal["iface_b_id"],
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["confirmed"] is True
    assert "cross_fw_checks" in data
    assert "purdue_suggestions" in data
    # Link should now be confirmed — re-check proposals
    state2 = client.get("/topology/state").json()
    # At least one proposal consumed
    assert len(state2["pending_proposals"]) < len(state["pending_proposals"])


def test_api_set_upstream(client):
    # firewall_name is a query parameter on the endpoint — pass via params=
    client.post(
        "/ingest/fortigate-config",
        files={"file": ("fw1.conf", _CONFIG_FW1.encode(), "text/plain")},
        params={"firewall_name": "FW-Perimeter"},
    )
    client.post(
        "/ingest/fortigate-config",
        files={"file": ("fw2.conf", _CONFIG_FW2.encode(), "text/plain")},
        params={"firewall_name": "FW-Core"},
    )
    state = client.get("/topology/state").json()
    fw1_id = next(f["id"] for f in state["firewalls"] if f["name"] == "FW-Perimeter")
    fw2_id = next(f["id"] for f in state["firewalls"] if f["name"] == "FW-Core")
    resp = client.post("/topology/set-upstream", json={
        "firewall_id":          fw2_id,
        "upstream_firewall_id": fw1_id,
        "purdue_level_ingress": 4,
        "purdue_level_egress":  3,
    })
    assert resp.status_code == 200
    data = resp.json()
    assert data["updated"] is True
    assert data["firewall"]["upstream_firewall_id"] == fw1_id
    assert data["firewall"]["purdue_level_ingress"] == 4
    assert data["firewall"]["purdue_level_egress"] == 3
    # Confirm state now has ingress/egress
    state2 = client.get("/topology/state").json()
    fw2_state = next(f for f in state2["firewalls"] if f["id"] == fw2_id)
    assert fw2_state["purdue_level_ingress"] == 4
    assert fw2_state["purdue_level_egress"] == 3


def test_api_suggest_purdue_endpoint(client):
    client.post(
        "/ingest/fortigate-config",
        files={"file": ("fw1.conf", _CONFIG_FW1.encode(), "text/plain")},
        data={"firewall_name": "FW-Perimeter"},
    )
    resp = client.post("/topology/suggest-purdue")
    assert resp.status_code == 200
    data = resp.json()
    assert "interfaces_updated" in data
    assert "by_source" in data


def test_api_run_checks_returns_suggestion_stats(client):
    client.post(
        "/ingest/fortigate-config",
        files={"file": ("fw1.conf", _CONFIG_FW1.encode(), "text/plain")},
        data={"firewall_name": "FW-Perimeter"},
    )
    client.post(
        "/ingest/fortigate-config",
        files={"file": ("fw2.conf", _CONFIG_FW2.encode(), "text/plain")},
        data={"firewall_name": "FW-Core"},
    )
    resp = client.post("/topology/run-checks")
    assert resp.status_code == 200
    data = resp.json()
    assert "purdue_suggestions" in data
    assert "links_analysed" in data
