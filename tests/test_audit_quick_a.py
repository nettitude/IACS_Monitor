"""
Audit quick-fix batch A:

  B-02  syslog_vendors: linear-time regexes + line-length cap (ReDoS)
  B-05  alert_engine: session-end actions count as permitted traffic
  B-19  alert_engine.check_log_silence: no false positive on ``logdesc``
"""
import time
from datetime import datetime, timezone

import pytest
from sqlalchemy import create_engine
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, configure_sqlite_engine
from app.models import ApprovedHost, Baseline, Finding, FortiAnalyzerEvent, Host
from app.parsers import alert_engine as ae
from app.parsers import syslog_vendors as sv


@pytest.fixture
def db():
    engine = create_engine("sqlite://", connect_args={"check_same_thread": False},
                           poolclass=StaticPool)
    configure_sqlite_engine(engine)
    Base.metadata.create_all(engine)
    s = sessionmaker(bind=engine)()
    yield s
    s.close()
    engine.dispose()


# ------------------------------------------------------------------ B-02 --

_BASES = {
    "106100": "%ASA-4-106100: access-list x denied tcp in/1.1.1.1(1) -> out/2.2.2.2(2) hit-cnt 1",
    "106100_user": "%ASA-4-106100: access-list x denied tcp in/1.1.1.1(1) (u) -> out/2.2.2.2(2)",
    "106023": '%ASA-4-106023: Deny tcp src in:1.1.1.1/1 dst out:2.2.2.2/2 by access-group "x"',
    "106001": "%ASA-2-106001: Inbound TCP connection denied from 1.1.1.1/1 to 2.2.2.2/2 flags SYN",
    "106015": "%ASA-6-106015: Deny TCP (no connection) from 1.1.1.1/1 to 2.2.2.2/2 flags SYN",
    "302014": "%ASA-6-302014: Teardown TCP connection 1 for in:1.1.1.1/1 to out:2.2.2.2/2 "
              "duration 0:00:01 bytes 1",
    "113004": "%ASA-6-113004: AAA user authentication Successful : server = 1.1.1.1 : user = bob",
    "113005": "%ASA-6-113005: AAA user authentication Rejected : reason = x : server = 1.1.1.1 : user = bob",
    "733100": "%ASA-4-733100: [ ",
    "pfsense": "Jan 1 00:00:00 fw filterlog[1]: 5,,,1,em0,match,pass,in,4,0x0,,64,1,0,none,6,tcp,",
    "panos": "1,2020/01/01 00:00:00,1,TRAFFIC,end,",
    "forti": 'date=2020-01-01 time=00:00:00 devname="a" type="traffic" ',
}


@pytest.mark.parametrize("name", sorted(_BASES))
@pytest.mark.parametrize("fill", [" ", "\t", "[ ", ",", " x"])
def test_adversarial_lines_finish_fast(name, fill):
    line = _BASES[name] + fill * (20000 // len(fill)) + "["
    t0 = time.perf_counter()
    sv.parse_syslog_any(line)
    for hint in ("cisco_asa", "pfsense", "panos", "fortinet"):
        sv.parse_syslog_any(line, hint)
    assert time.perf_counter() - t0 < 0.5


def test_original_106100_repro_is_fast():
    line = _BASES["106100"] + " " * 2000 + "["
    t0 = time.perf_counter()
    sv.parse_asa_line(line)
    assert time.perf_counter() - t0 < 0.5


def test_regexes_linear_without_the_cap(monkeypatch):
    """The regexes themselves (not just the cap) must be linear."""
    monkeypatch.setattr(sv, "MAX_LINE_CHARS", 10 ** 9)
    for name in ("106100", "106001", "106015", "113004", "113005", "733100"):
        line = _BASES[name] + " " * 30000 + "["
        t0 = time.perf_counter()
        sv.parse_asa_line(line)
        assert time.perf_counter() - t0 < 0.5, name


def test_line_cap_applies_and_valid_line_still_parses():
    assert sv.MAX_LINE_CHARS == 8192
    assert sv._cap_line("a" * 20000) == "a" * 8192
    # valid ASA line followed by a huge tail: truncated, still parsed, no hang
    r = sv.parse_asa_line(_BASES["106100"] + " " * 50000 + "[0xab]")
    assert r is not None and r["action"] == "deny"


@pytest.mark.parametrize("tail,ok", [
    ("", True), ("  ", True), (" first hit [0x1a2b, 0x3c]", True), (" [0xab]", True),
    (" 300-second interval [0x1, 0x2]  ", True), (" x[0x1]y", False),
    ("x", False), (" [unterminated", False),
])
def test_106100_tail_semantics_unchanged(tail, ok):
    r = sv.parse_asa_line(_BASES["106100"] + tail)
    assert (r is not None) is ok


def test_split_based_parsers_keep_results():
    r = sv.parse_asa_line("%ASA-6-113005: AAA user authentication Rejected : reason = Invalid "
                          "password : server = 10.1.1.1 : user = bob : user IP = 1.2.3.4")
    assert r["user"] == "bob" and r["src_ip"] == "1.2.3.4" and r["action"] == "failed"
    r = sv.parse_asa_line("%ASA-6-106015: Deny TCP (no connection) from 1.1.1.1/1 to "
                          "2.2.2.2/2 flags RST ACK  on interface inside")
    assert r["action"] == "deny" and r["src_ip"] == "1.1.1.1"
    r = sv.parse_asa_line("%ASA-4-733100: [ 10.1.1.1 ] drop rate-1 exceeded. Current burst "
                          "rate is 5 per second, max configured rate is 3")
    assert r["src_ip"] == "10.1.1.1" and r["action"] == "deny"


# ------------------------------------------------------------------ B-05 --

def _mk(db, action, src="10.4.0.5", dst="10.1.0.5", port=502, log_type="traffic", **kw):
    e = FortiAnalyzerEvent(source_type="api_push", log_type=log_type, action=action,
                           src_ip=src, dst_ip=dst, dst_port=port, device_name="FGT1",
                           received_at=datetime.now(timezone.utc), raw_fields={}, **kw)
    db.add(e)
    db.flush()
    return e


PERMITTED = ["accept", "allow", "allowed", "permit", "close", "timeout", "client-rst",
             "server-rst", "start", "ip-conn", "Close", "accept: session close"]
NOT_PERMITTED = ["deny", "drop", "block", "blocked", "reject", "reset", "dropped",
                 "reset-by-policy", "dns", "", None, "failed"]


@pytest.mark.parametrize("a", PERMITTED)
def test_is_permitted_true(a):
    assert ae._is_permitted(a)


@pytest.mark.parametrize("a", NOT_PERMITTED)
def test_is_permitted_false(a):
    assert not ae._is_permitted(a)


def test_asa_teardown_normalises_to_permitted_action():
    r = sv.parse_asa_line(_BASES["302014"])
    assert r["action"] == "close" and ae._is_permitted(r["action"])


@pytest.mark.parametrize("action", ["close", "timeout", "client-rst", "server-rst",
                                    "accept: session close", "start"])
def test_it_ot_bypass_fires_for_session_end(db, action):
    db.add_all([Host(ip="10.4.0.5", purdue_level=4), Host(ip="10.1.0.5", purdue_level=1)])
    db.flush()
    assert ae.check_it_ot_bypass(_mk(db, action), db) is not None
    assert ae.check_it_ot_bypass(_mk(db, "deny"), db) is None


@pytest.mark.parametrize("action", ["close", "timeout", "client-rst", "server-rst"])
def test_other_checks_fire_for_session_end(db, action):
    db.add(Host(ip="10.1.0.7", purdue_level=1))
    b = Baseline(name="B", is_active=True)
    db.add(b)
    db.flush()
    db.add(ApprovedHost(baseline_id=b.id, ip="10.0.2.50", role="jump_host"))
    db.flush()
    assert ae.check_ot_internet_egress(_mk(db, action, src="10.1.0.7", dst="8.8.8.8", port=53), db)
    assert ae.check_ot_internet_egress(_mk(db, "deny", src="10.1.0.7", dst="8.8.8.8", port=53), db) is None
    assert ae.check_remote_access_bypass(
        _mk(db, action, src="198.51.100.9", dst="10.0.2.21", port=3389), db)
    assert ae.check_remote_access_bypass(
        _mk(db, "deny", src="198.51.100.9", dst="10.0.2.21", port=3389), db) is None
    assert ae.check_unauth_ot_write(_mk(db, action, src="10.3.0.20", dst="10.1.0.5", port=502), db)
    assert ae.check_unauth_ot_write(_mk(db, "deny", src="10.3.0.21", dst="10.1.0.5", port=502), db) is None


def test_accept_then_close_dedups_to_one_finding(db):
    db.add_all([Host(ip="10.4.0.5", purdue_level=4), Host(ip="10.1.0.5", purdue_level=1)])
    db.flush()
    for a in ("accept", "close", "timeout", "client-rst"):
        ae.evaluate_event(_mk(db, a), db)
    n = db.query(Finding).filter(Finding.check_name == "it_ot_bypass").count()
    assert n == 1


# ------------------------------------------------------------------ B-19 --

def _event(db, subtype="system", raw=None, msg="x"):
    e = FortiAnalyzerEvent(source_type="api_push", log_type="event", subtype=subtype,
                           device_name="FGT1", raw_message=msg, raw_fields=raw or {},
                           received_at=datetime.now(timezone.utc))
    db.add(e)
    db.flush()
    return e


def test_log_silence_ignores_logdesc_field(db):
    e = _event(db, raw={"logdesc": "Admin login successful", "type": "event",
                        "subtype": "system", "msg": "Administrator admin logged in"})
    assert ae.check_log_silence(e, db) is None
    e2 = _event(db, raw={"logdesc": "IP address assigned"}, msg='logdesc="IP address assigned"')
    assert ae.check_log_silence(e2, db) is None


@pytest.mark.parametrize("raw", [
    {"msg": "Device offline"}, {"msg": "logd stopped responding"},
    {"logdesc": "Logging disabled", "msg": "x"}, {"msg": "connection lost to FortiAnalyzer"},
    {"msg": "no logs received"}, {"daemon": "logd"},
])
def test_log_silence_still_fires(db, raw):
    f = ae.check_log_silence(_event(db, raw=raw), db)
    assert f is not None and f.check_name == "log_silence"
