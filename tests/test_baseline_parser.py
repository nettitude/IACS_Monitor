"""
Tests for app/parsers/baseline_parser.py.

Uses an in-memory SQLite database populated with the minimum rows
required for each assertion.
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base
from app.models import (
    ApprovedCommsEntry,
    ApprovedHost,
    Baseline,
    FirewallRule,
    Host,
)
from app.parsers.baseline_parser import (
    get_or_create_baseline,
    ingest_approved_comms,
    ingest_approved_hosts,
    ingest_asset_inventory,
    ingest_reviewed_policies,
)


@pytest.fixture
def db():
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


# ─────────────────────────────────────────── get_or_create_baseline ──────────


def test_get_or_create_baseline_new(db):
    b = get_or_create_baseline(db, "Baseline-2025-Q1", description="Q1 review")
    assert b.id is not None
    assert b.name == "Baseline-2025-Q1"
    assert b.is_active is True


def test_get_or_create_baseline_existing(db):
    b1 = get_or_create_baseline(db, "My-Baseline")
    db.commit()
    b2 = get_or_create_baseline(db, "My-Baseline")
    assert b1.id == b2.id


# ─────────────────────────────────────────── ingest_approved_comms ───────────


def test_ingest_comms_basic(db):
    csv = "src,dst,dst_port\n10.0.1.1,10.0.1.10,502\n10.0.1.2,10.0.1.10,102\n"
    result = ingest_approved_comms(csv, db, "B1")
    assert result["entries_loaded"] == 2
    assert db.query(ApprovedCommsEntry).count() == 2


def test_ingest_comms_alias_columns(db):
    csv = "source,destination,port\n10.0.1.1,10.0.1.10,80\n"
    result = ingest_approved_comms(csv, db, "B1")
    assert result["entries_loaded"] == 1
    entry = db.query(ApprovedCommsEntry).first()
    assert entry.src == "10.0.1.1"
    assert entry.dst == "10.0.1.10"


def test_ingest_comms_missing_src_skipped(db):
    csv = "src,dst,dst_port\n,10.0.1.10,502\n10.0.1.2,10.0.1.10,502\n"
    result = ingest_approved_comms(csv, db, "B1")
    assert result["skipped"] >= 1
    assert result["entries_loaded"] == 1


# ─────────────────────────────────────────── ingest_approved_hosts ───────────


def test_ingest_approved_hosts(db):
    csv = "ip,mac,role\n10.0.1.50,aa:bb:cc:dd:ee:ff,jump_host\n10.0.1.51,aa:bb:cc:dd:ee:00,hmi\n"
    result = ingest_approved_hosts(csv, db, "B1")
    assert result["hosts_loaded"] == 2
    hosts = db.query(ApprovedHost).all()
    roles = {h.role for h in hosts}
    assert "jump_host" in roles
    assert "hmi" in roles


def test_ingest_approved_hosts_bad_role_skipped(db):
    csv = "ip,mac,role\n10.0.1.50,aa:bb:cc:dd:ee:ff,unknown_role\n10.0.1.51,aa:bb:cc:dd:ee:00,jump_host\n"
    result = ingest_approved_hosts(csv, db, "B1")
    assert result["skipped_bad_role"] >= 1
    assert result["hosts_loaded"] == 1


# ─────────────────────────────────────────── ingest_asset_inventory ──────────


def test_ingest_asset_inventory_creates_hosts(db):
    csv = "ip,mac,hostname\n10.0.1.100,aa:bb:cc:00:00:01,plc-01\n10.0.1.101,aa:bb:cc:00:00:02,hmi-01\n"
    result = ingest_asset_inventory(csv, db, "B1")
    assert result["hosts_created_or_updated"] == 2
    assert db.query(Host).count() == 2


def test_ingest_asset_inventory_sets_manual_classification(db):
    csv = "ip,mac,device_type\n10.0.1.100,aa:bb:cc:00:00:01,plc\n"
    ingest_asset_inventory(csv, db, "B1")
    host = db.query(Host).filter(Host.ip == "10.0.1.100").first()
    assert host is not None
    assert host.device_type == "plc"
    assert host.classification_source == "manual"


# ─────────────────────────────────────────── ingest_reviewed_policies ────────


def test_ingest_reviewed_policies(db):
    # Insert a FirewallRule that the policy CSV will reference by policy_id.
    rule = FirewallRule(
        device_name="fw1",
        device_type="fortigate",
        src="any",
        dst="any",
        action="permit",
        policy_id="10",
    )
    db.add(rule)
    db.commit()

    csv = "policy_id,conduit,owner\n10,Modbus-Conduit,OT-Team\n"
    result = ingest_reviewed_policies(csv, db, "B1")
    assert result["policies_matched"] == 1

    db.refresh(rule)
    assert rule.conduit == "Modbus-Conduit"
    assert rule.owner == "OT-Team"
