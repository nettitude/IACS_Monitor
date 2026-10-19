"""
Tests for app/parsers/traffic_findings.py
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.models import (
    Base,
    ApprovedHost,
    Baseline,
    Finding,
    Host,
    NetworkSession,
    ProtocolDetail,
)
from app.parsers.traffic_findings import check_unauthorized_industrial_writes


# ---------------------------------------------------------------------------
# DB fixture
# ---------------------------------------------------------------------------

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


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _make_baseline(db, name="test-baseline", is_active=True):
    bl = Baseline(name=name, is_active=is_active)
    db.add(bl)
    db.flush()
    return bl


def _make_approved_host(db, baseline_id, ip, role="engineering_ws"):
    ah = ApprovedHost(baseline_id=baseline_id, ip=ip, role=role)
    db.add(ah)
    db.flush()
    return ah


def _make_write_session(db, src_ip, dst_ip="10.0.0.5", protocol="modbus",
                         function_code=16, operation="write"):
    """Create a Host pair, NetworkSession, and ProtocolDetail for a write."""
    src_host = Host(ip=src_ip, sources=["pcap"])
    dst_host = Host(ip=dst_ip, sources=["pcap"])
    db.add_all([src_host, dst_host])
    db.flush()

    session = NetworkSession(
        src_host_id=src_host.id,
        dst_host_id=dst_host.id,
        src_port=12345,
        dst_port=502,
        transport="tcp",
        protocol=protocol,
        packet_count=1,
        byte_count=100,
    )
    db.add(session)
    db.flush()

    detail = ProtocolDetail(
        session_id=session.id,
        protocol=protocol,
        direction="request",
        summary="write_multiple_registers",
        fields={"operation": operation, "function_code": function_code},
    )
    db.add(detail)
    db.commit()
    return session, detail


# ---------------------------------------------------------------------------
# Tests
# ---------------------------------------------------------------------------

def test_no_sessions_no_findings(db):
    """No ProtocolDetail rows -> zero findings created."""
    stats = check_unauthorized_industrial_writes(db)
    assert stats["findings_created"] == 0
    assert stats["writes_examined"] == 0


def test_modbus_write_from_unapproved_host_creates_finding(db):
    """A Modbus write from a host not in the approved list creates a critical finding."""
    _make_write_session(db, src_ip="10.0.0.99")

    stats = check_unauthorized_industrial_writes(db)

    assert stats["findings_created"] == 1
    finding = db.query(Finding).first()
    assert finding is not None
    assert finding.severity == "critical"
    assert finding.check_name == "unauthorized_industrial_write"


def test_modbus_write_from_approved_engineering_ws_no_finding(db):
    """A write from an approved engineering_ws host does NOT create a finding."""
    bl = _make_baseline(db)
    _make_approved_host(db, bl.id, ip="10.0.0.1", role="engineering_ws")
    _make_write_session(db, src_ip="10.0.0.1")

    stats = check_unauthorized_industrial_writes(db)

    assert stats["findings_created"] == 0
    assert db.query(Finding).count() == 0


def test_modbus_read_does_not_create_finding(db):
    """A read operation (not a write) never creates a finding."""
    src_host = Host(ip="10.0.0.50", sources=["pcap"])
    dst_host = Host(ip="10.0.0.5", sources=["pcap"])
    db.add_all([src_host, dst_host])
    db.flush()

    session = NetworkSession(
        src_host_id=src_host.id, dst_host_id=dst_host.id,
        src_port=12345, dst_port=502, transport="tcp",
        protocol="modbus", packet_count=1, byte_count=50,
    )
    db.add(session)
    db.flush()

    detail = ProtocolDetail(
        session_id=session.id, protocol="modbus",
        direction="request", summary="read_holding_registers",
        fields={"operation": "read", "function_code": 3},
    )
    db.add(detail)
    db.commit()

    stats = check_unauthorized_industrial_writes(db)

    assert stats["findings_created"] == 0
    assert stats["writes_examined"] == 0


def test_finding_deduplication_on_rerun(db):
    """Running the check twice for the same write creates only one finding."""
    _make_write_session(db, src_ip="10.0.0.88")

    stats1 = check_unauthorized_industrial_writes(db)
    stats2 = check_unauthorized_industrial_writes(db)

    assert stats1["findings_created"] == 1
    assert stats2["findings_created"] == 0
    assert stats2["already_flagged"] == 1
    assert db.query(Finding).count() == 1


def test_no_active_baseline_all_writes_flagged(db):
    """When there is no active baseline, every write is flagged (fail open)."""
    # Create an inactive baseline and an approved host under it
    bl = _make_baseline(db, is_active=False)
    _make_approved_host(db, bl.id, ip="10.0.0.99", role="engineering_ws")
    # Even though the host would be approved under an active baseline,
    # without one, the host lookup returns nothing and the write is flagged.
    _make_write_session(db, src_ip="10.0.0.99")

    stats = check_unauthorized_industrial_writes(db)

    assert stats["findings_created"] == 1


def test_approved_hmi_host_no_finding(db):
    """HMI role is also approved for writes; no finding should be raised."""
    bl = _make_baseline(db)
    _make_approved_host(db, bl.id, ip="192.168.1.10", role="hmi")
    _make_write_session(db, src_ip="192.168.1.10", protocol="dnp3")

    stats = check_unauthorized_industrial_writes(db)

    assert stats["findings_created"] == 0


def test_dnp3_write_from_unapproved_host_creates_finding(db):
    """DNP3 write is also covered by the check."""
    _make_write_session(db, src_ip="10.0.0.77", protocol="dnp3")

    stats = check_unauthorized_industrial_writes(db)

    assert stats["findings_created"] == 1
    finding = db.query(Finding).first()
    assert finding.detail["protocol"] == "dnp3"


def test_finding_source_ref_is_grouped_operation_key(db):
    """T3-33: source_ref keys the (capture, protocol, function, client, server)
    group rather than one ProtocolDetail; the detail ids are kept as evidence."""
    _session, detail = _make_write_session(db, src_ip="10.0.0.33")

    check_unauthorized_industrial_writes(db)

    finding = db.query(Finding).first()
    assert finding.source_ref.startswith("industrial_op:")
    assert "modbus:write_multiple_registers" in finding.source_ref
    assert finding.detail["protocol_detail_ids"] == [detail.id]
    assert finding.detail["occurrences"] == 1


def test_multiple_writes_different_hosts_multiple_findings(db):
    """Two writes from two different unapproved hosts each get their own finding."""
    _make_write_session(db, src_ip="10.0.0.11", dst_ip="10.0.0.100")
    _make_write_session(db, src_ip="10.0.0.22", dst_ip="10.0.0.101")

    stats = check_unauthorized_industrial_writes(db)

    assert stats["findings_created"] == 2
    assert db.query(Finding).count() == 2


def test_finding_detail_contains_src_ip(db):
    """Finding.detail['src_ip'] reflects the actual source IP."""
    _make_write_session(db, src_ip="172.16.0.50")

    check_unauthorized_industrial_writes(db)

    finding = db.query(Finding).first()
    assert finding.detail["src_ip"] == "172.16.0.50"
