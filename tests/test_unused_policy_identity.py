"""unused_policy findings are keyed on the logical rule (stable across config
re-ingest), so re-importing a config neither duplicates them nor closes and
reopens them - an operator's acknowledgement survives."""
from pathlib import Path

from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, configure_sqlite_engine
from app.models import Finding
from app.parsers.alert_engine import review_unused_policies
from app.parsers.forti_config_parser import ingest_fortigate_config

CFG = (Path(__file__).resolve().parent.parent / "sample_data" / "sample_fortigate_config.txt").read_text()


def _db():
    eng = create_engine("sqlite://", connect_args={"check_same_thread": False}, poolclass=StaticPool)
    configure_sqlite_engine(eng)
    Base.metadata.create_all(eng)
    return sessionmaker(bind=eng)()


def _unused(db, status=None):
    q = db.query(Finding).filter(Finding.check_name == "unused_policy")
    return q.filter(Finding.status == status).all() if status else q.all()


def _one_session(db):
    """AU full review B4: with no traffic at all the review is 'incomplete',
    not a storm of unused findings - give it one observed session."""
    from datetime import datetime, timezone
    from app.models import Host, NetworkSession
    a = Host(ip="192.168.1.10", mac="aa:aa:aa:aa:aa:01")
    b = Host(ip="10.10.10.5", mac="aa:aa:aa:aa:aa:02")
    db.add_all([a, b]); db.flush()
    db.add(NetworkSession(src_host_id=a.id, dst_host_id=b.id, dst_port=443, protocol="tcp",
                          transport="tcp", first_seen=datetime.now(timezone.utc),
                          last_seen=datetime.now(timezone.utc), packet_count=1, byte_count=100))
    db.commit()


def test_acknowledgement_survives_reingest():
    db = _db()
    ingest_fortigate_config(CFG, db, firewall_name="FW-OT")
    _one_session(db)
    review_unused_policies(db); db.commit()
    first = _unused(db)
    assert first, "sample config should yield unused permit rules (one unrelated session loaded)"
    # one finding per logical policy, not per expanded row
    pids = [f.detail.get("policy_id") for f in first]
    assert len(pids) == len(set(pids))
    ack = first[0]
    ack.status = "acknowledged"; ack.acknowledged_by = "op"
    db.commit()

    ingest_fortigate_config(CFG, db, firewall_name="FW-OT")   # new FirewallRule row ids
    review_unused_policies(db); db.commit()

    after = _unused(db)
    assert len(after) == len(first)                           # no duplicates
    assert db.get(Finding, ack.id).status == "acknowledged"   # untouched
    open_pids = {f.detail.get("policy_id") for f in _unused(db, "open")}
    assert ack.detail.get("policy_id") not in open_pids        # no fresh open twin
