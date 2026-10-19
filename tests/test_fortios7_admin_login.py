"""
FortiOS 7.x admin login events (owner, 2026-10-13: "yes, fix the auth failure check").

FortiOS 7.x logs an admin login as type=event subtype=system action="login" with
the outcome in status= (logid 0100032001 success / 0100032002 failed).  The
auth_failure check only knew subtype login / authentication with the outcome in
action=, so real FortiGate login failures raised nothing.  Both shapes count now.
"""
import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker

from app.db import Base, configure_sqlite_engine
from app.models import Finding
from app.parsers.alert_engine import _login_outcome, evaluate_event
from app.parsers.forti_parser import ingest_syslog_line_ex


def _line(t, logid, status, user="admin", src="10.40.1.66", action="login", subtype="system"):
    return (f'<185>Oct 13 08:41:{t:02d} FGT-PLANT-T date=2026-10-13 time=08:41:{t:02d} devname="FGT-PLANT-T" '
            f'devid="FG100FTK23000001" logid="{logid}" type="event" subtype="{subtype}" level="alert" vd="root" '
            f'logdesc="Admin login" user="{user}" ui="https({src})" method="https" srcip={src} dstip=10.40.1.1 '
            f'action="{action}" status="{status}" reason="passwd_invalid" msg="Administrator {user} login"')


@pytest.fixture
def db():
    engine = create_engine("sqlite:///:memory:", connect_args={"check_same_thread": False})
    configure_sqlite_engine(engine)
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()


def _ev(db, line):
    ev, st = ingest_syslog_line_ex(line, db)
    assert st == "created", line
    return ev


def test_fortios7_failed_login_raises_auth_failure(db):
    ev = _ev(db, _line(10, "0100032002", "failed"))
    assert _login_outcome(ev) == "failed"
    evaluate_event(ev, db)
    db.commit()
    (f,) = db.query(Finding).filter(Finding.check_name == "auth_failure").all()
    assert f.detail["user"] == "admin" and f.detail["src_ip"] == "10.40.1.66"


def test_repeated_failures_one_finding_per_hour(db):
    for t in range(6):
        evaluate_event(_ev(db, _line(10 + t * 4, "0100032002", "failed")), db)
    db.commit()
    f = db.query(Finding).filter(Finding.check_name == "auth_failure").all()
    assert len(f) == 1 and f[0].occurrence_count >= 6


@pytest.mark.parametrize("logid,status,want", [
    ("0100032001", "success", "success"),
    ("0100032002", "failed", "failed"),
    ("0100032002", "", "failed"),          # outcome from the logid when status= is missing
    ("0100032001", "", "success"),
])
def test_outcome_from_status_or_logid(db, logid, status, want):
    assert _login_outcome(_ev(db, _line(1 if want == "success" else 2, logid, status))) == want


def test_successful_fortios7_login_is_not_a_failure(db):
    evaluate_event(_ev(db, _line(3, "0100032001", "success")), db)
    db.commit()
    assert not db.query(Finding).filter(Finding.check_name == "auth_failure").count()


def test_other_system_events_are_not_logins(db):
    line = ('date=2026-10-13 time=08:44:00 devname="FGT-PLANT-T" logid="0100044547" type="event" '
            'subtype="system" logdesc="Object attribute configured" user="admin" action="Edit" '
            'cfgpath="firewall.policy" cfgobj="21" msg="Edit firewall.policy 21"')
    assert _login_outcome(_ev(db, line)) is None


def test_legacy_shape_still_counts(db):
    line = ('date=2026-09-30 time=12:03:01 devname="FGT-OT" logid="0100032099" '
            'type="event" subtype="login" user="admin" srcip=10.20.1.9 action="failed"')
    ev = _ev(db, line)
    assert _login_outcome(ev) == "failed"
    evaluate_event(ev, db)
    db.commit()
    assert db.query(Finding).filter(Finding.check_name == "auth_failure").count() == 1
