"""
Tier-3 findings-engine fixes in app/parsers/alert_engine.py:

  T3-15  check_scanning_denied windows on event_time (not DB insert time)
  T3-16  evaluate_event: one savepoint per real-time check
  T3-17  run_periodic_reviews: one savepoint per review, failures isolated
  T3-18  Phase-6 twins: batched traffic confirmation / open-finding lookups
  T3-19  Phase-6 twins: one finding per LOGICAL rule, re-ingest stable
  T3-20  related_checks evidence + distinct titles for overlapping twins
  ApprovedCommsEntry.dst_port_end ranges honoured by rule_conduit_drift
"""
import random
from datetime import datetime, timedelta, timezone
from pathlib import Path

import pytest
from sqlalchemy import create_engine, event, text
from sqlalchemy.orm import sessionmaker
from sqlalchemy.pool import StaticPool

from app.db import Base, configure_sqlite_engine
from app.models import (
    ApprovedCommsEntry, Baseline, Finding, Firewall, FirewallInterface,
    FirewallRule, FirewallZone, FortiAnalyzerEvent, Host, NetworkSession,
)
from app.parsers import alert_engine as ae
from app.parsers.alert_engine import (
    _make_finding, _rule_base_evidence, _rule_traffic_confirmed, _TrafficIndex,
    _TwinRunContext, _rule_zone_purdue, _dedup_key,
    check_scanning_denied, escalation_count, evaluate_event, failed_reviews,
    review_rule_cleartext_creds, review_rule_conduit_drift,
    review_rule_cleartext_protocols, review_rule_it_ot_bypass,
    review_rule_mgmt_wrong_zone, run_periodic_reviews,
)
from app.parsers.forti_config_parser import ingest_fortigate_config


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


def _now():
    return datetime.now(timezone.utc)


def _deny(db, src="10.9.9.9", event_time=None, received_at=None, port=1000):
    ev = FortiAnalyzerEvent(
        source_type="csv_import", log_type="traffic", action="deny",
        src_ip=src, dst_ip="10.1.1.1", dst_port=port, device_name="fw1",
        received_at=received_at or _now(), event_time=event_time, raw_fields={},
    )
    db.add(ev)
    db.flush()
    return ev


# ─── T3-15 scanning window keyed on event time ────────────────────────────────

class TestScanningWindow:
    def test_historical_file_spread_over_hours_no_finding(self, db):
        # A log file uploaded now: 60 denies whose own timestamps are 3 min
        # apart (3 hours of history), all inserted within the same second.
        t0 = datetime(2026, 9, 1, 8, 0, 0)
        inserted = _now()
        out = [check_scanning_denied(_deny(db, event_time=t0 + timedelta(minutes=3 * i),
                                          received_at=inserted, port=1000 + i), db)
               for i in range(60)]
        assert not any(out)
        assert db.query(Finding).filter(Finding.check_name == "scanning_denied").count() == 0

    def test_real_burst_fires(self, db):
        t0 = datetime(2026, 9, 1, 8, 0, 0)
        inserted = _now()
        out = [check_scanning_denied(_deny(db, event_time=t0 + timedelta(seconds=5 * i),
                                          received_at=inserted, port=1000 + i), db)
               for i in range(25)]
        created = [f for f in out if f]
        assert len(created) == 1  # one per src per event-hour
        f = created[0]
        assert f.detail["window_hour"] == "2026-09-01T08"
        assert f.detail["deny_count_in_window"] >= 20

    def test_historical_burst_detected_even_when_inserted_later(self, db):
        # Hours of quiet history plus one real burst inside it.
        t0 = datetime(2026, 9, 1, 8, 0, 0)
        inserted = _now()
        for i in range(30):
            check_scanning_denied(_deny(db, event_time=t0 + timedelta(minutes=10 * i),
                                        received_at=inserted), db)
        burst = t0 + timedelta(hours=2, minutes=1)
        out = [check_scanning_denied(_deny(db, event_time=burst + timedelta(seconds=i),
                                          received_at=inserted), db) for i in range(22)]
        assert sum(1 for f in out if f) == 1

    def test_falls_back_to_received_at_without_event_time(self, db):
        base = _now()
        out = [check_scanning_denied(_deny(db, received_at=base + timedelta(seconds=i)), db)
               for i in range(21)]
        assert sum(1 for f in out if f) == 1


# ─── T3-16 evaluate_event isolation ───────────────────────────────────────────

def _bad_check(ev, db):
    # Writes a finding, then hits a DB error (on PostgreSQL this would abort
    # the whole transaction without the savepoint).
    _make_finding(db, "log_silence", "partial write from bad check", "x",
                  {"device_name": "bad-check"})
    db.execute(text("SELECT * FROM no_such_table"))


def _good_check(ev, db):
    # device_name is part of the dedup key (subtype is not), so give each
    # event its own identity; a second call for the same event dedups.
    return _make_finding(db, "ha_system_error", "good check", "x",
                         {"device_name": f"good-{ev.id}"})


class TestEvaluateEventIsolation:
    def test_db_error_in_one_check_does_not_block_others(self, db, monkeypatch, caplog):
        monkeypatch.setattr(ae, "_RT_CHECKS", [_good_check, _bad_check, _good_check])
        ev = _deny(db)
        with caplog.at_level("ERROR", logger=ae.log.name):
            out = evaluate_event(ev, db)
        assert [f.title for f in out] == ["good check"]  # 2nd good is a dedup
        db.commit()  # session still usable, commit succeeds
        titles = [f.title for f in db.query(Finding)]
        assert titles == ["good check"]  # bad check's partial write rolled back
        assert sum("_bad_check" in r.getMessage() for r in caplog.records) == 1
        assert "no_such_table" in caplog.text  # traceback logged

        # later event: still works on the same session
        ev2 = _deny(db)
        assert len(evaluate_event(ev2, db)) == 1
        db.commit()

    def test_escalation_counter_restored_on_rollback(self, db, monkeypatch):
        f = _make_finding(db, "log_silence", "t", "x", {"device_name": "d"}, severity="low")
        db.commit()

        def escalate_then_fail(ev, db):
            _make_finding(db, "log_silence", "t2", "x", {"device_name": "d"}, severity="high")
            raise RuntimeError("boom")

        monkeypatch.setattr(ae, "_RT_CHECKS", [escalate_then_fail])
        evaluate_event(_deny(db), db)
        db.commit()
        assert escalation_count(db) == 0
        db.refresh(f)
        assert f.severity == "low"

        def escalate_ok(ev, db):
            _make_finding(db, "log_silence", "t3", "x", {"device_name": "d"}, severity="high")

        monkeypatch.setattr(ae, "_RT_CHECKS", [escalate_ok])
        evaluate_event(_deny(db), db)
        db.commit()
        assert escalation_count(db) == 1
        db.refresh(f)
        assert f.severity == "high"


# ─── shared FW topology for Phase-6 tests ─────────────────────────────────────

@pytest.fixture
def fw(db):
    fw = Firewall(name="FGT1", device_name="FGT1", vendor="fortigate")
    db.add(fw)
    db.flush()
    for name, lvl in [("port1", 3), ("port2", 1), ("port3", 2), ("port4", 4)]:
        db.add(FirewallInterface(firewall_id=fw.id, name=name, purdue_level=lvl))
    for zone, iface in [("IT_ZONE", "port1"), ("OT_ZONE", "port2"), ("OT_ZONE", "port3")]:
        db.add(FirewallZone(device_name="FGT1", interface_name=iface, zone_name=zone))
    db.flush()
    return fw


def _rule(db, fw, src_zone="IT_ZONE", dst_zone="OT_ZONE", dst_port="23",
          policy_id="10", protocol="tcp", dst="all", raw_line=None, enabled=True):
    r = FirewallRule(
        firewall_id=fw.id, device_name="FGT1", device_type="fortigate",
        policy_id=policy_id, src_zone=src_zone, dst_zone=dst_zone, src="all",
        dst=dst, protocol=protocol, dst_port=dst_port, action="accept",
        raw_line=raw_line, enabled=enabled,
    )
    db.add(r)
    db.flush()
    return r


_HOST_SEQ = iter(range(1, 60_000))


def _unique_ip(level):
    # F-01: random IPs collided on the hosts.ip unique index (flaky
    # IntegrityError, ~3% of runs); a counter keeps every host distinct.
    n = next(_HOST_SEQ)
    return f"10.{level}.{n // 250}.{n % 250 + 1}"


def _session(db, src_level, dst_level, dst_port, transport="tcp"):
    src = Host(ip=_unique_ip(src_level), purdue_level=src_level)
    dst = Host(ip=_unique_ip(dst_level), purdue_level=dst_level)
    db.add_all([src, dst])
    db.flush()
    db.add(NetworkSession(src_host_id=src.id, dst_host_id=dst.id, dst_port=dst_port,
                          transport=transport))
    db.flush()


# ─── T3-17 run_periodic_reviews isolation ─────────────────────────────────────

class TestPeriodicIsolation:
    def test_failing_review_isolated_others_committed(self, db, fw, monkeypatch, caplog):
        _rule(db, fw)
        db.commit()

        def broken(db):
            _make_finding(db, "log_silence", "partial from broken review", "x",
                          {"device_name": "broken"})
            db.execute(text("SELECT * FROM no_such_table"))

        broken.__name__ = "review_ghost_vlans"
        monkeypatch.setattr(ae, "review_ghost_vlans", broken)
        with caplog.at_level("ERROR", logger=ae.log.name):
            stats = run_periodic_reviews(db)

        assert stats["review_ghost_vlans"] == 0
        assert all(isinstance(v, int) for v in stats.values())
        assert sum(stats.values()) >= 4  # callers' summing still works
        assert failed_reviews(db) == ["review_ghost_vlans"]
        assert "no_such_table" in caplog.text

        # committed: visible from a brand-new session on the same engine
        other = sessionmaker(bind=db.get_bind())()
        names = {f.check_name for f in other.query(Finding)}
        other.close()
        assert {"rule_cleartext_protocol", "rule_it_ot_bypass"} <= names
        assert "log_silence" not in names

    def test_failing_twin_does_not_lose_other_twins(self, db, fw, monkeypatch):
        _rule(db, fw)
        db.commit()

        def boom(db, _resolver=None, _ctx=None):
            review_rule_cleartext_protocols(db, _resolver=_resolver, _ctx=_ctx)
            raise RuntimeError("twin exploded after writing")

        boom.__name__ = "review_rule_cleartext_protocols"
        monkeypatch.setattr(ae, "_RULE_TWIN_CHECKS",
                            (boom,) + tuple(ae._RULE_TWIN_CHECKS[1:]))
        stats = run_periodic_reviews(db)
        assert stats["review_rule_cleartext_protocols"] == 0
        assert stats["review_rule_cleartext_creds"] == 1
        fs = {f.check_name: f for f in db.query(Finding).filter(Finding.check_name.like("rule_%"))}
        assert "rule_cleartext_protocol" not in fs
        # related_checks only lists twins whose writes survived
        assert "rule_cleartext_protocol" not in fs["rule_cleartext_creds"].detail["related_checks"]


# ─── T3-18 batched queries ────────────────────────────────────────────────────

def _count_selects(db):
    counter = {"n": 0}

    def _c(conn, cur, stmt, params, ctx, many):
        if stmt.lstrip().upper().startswith("SELECT"):
            counter["n"] += 1

    event.listen(db.get_bind(), "before_cursor_execute", _c)
    return counter, lambda: event.remove(db.get_bind(), "before_cursor_execute", _c)


def _synthetic(db, fw, n, seed=1):
    rnd = random.Random(seed)
    zones = ["port1", "port2", "port3", "port4", "IT_ZONE", "OT_ZONE"]
    ports = ["23", "22", "53", "502", "80", "1-1024", "any", "445", "3389", "8080-8090"]
    for i in range(n):
        s, d = rnd.sample(zones, 2)
        _rule(db, fw, s, d, rnd.choice(ports), policy_id=str(1000 + i))
    for _ in range(40):
        _session(db, rnd.choice([1, 2, 3, 4]), rnd.choice([1, 2, 3, 4]),
                 rnd.choice([23, 22, 53, 502, 80, 445, 9999]))
    db.add(ApprovedCommsEntry(baseline_id=_baseline(db).id, src="x", dst="y",
                              dst_port=502, protocol="tcp"))
    db.commit()


def _baseline(db):
    b = Baseline(name="b", is_active=True)
    db.add(b)
    db.flush()
    return b


def _run_twins(db):
    ctx = _TwinRunContext(db, _rule_zone_purdue(db))
    n = sum(len(fn(db, _ctx=ctx)) for fn in ae._RULE_TWIN_CHECKS)
    db.flush()
    return n


class TestBatchedQueries:
    def test_select_count_independent_of_rule_count(self, db, fw):
        _synthetic(db, fw, 40)
        counter, stop = _count_selects(db)
        n_small = _run_twins(db)
        small = counter["n"]
        stop()
        assert n_small > 20
        # 20 + 1 (MP-15 boundary load) + 3 (MP-23 VPN context) + 1 (rule_mgmt_protocol
        # twin): fixed costs
        assert small <= 25

    def test_select_count_500_rules_constant(self, db, fw):
        _synthetic(db, fw, 500)
        counter, stop = _count_selects(db)
        n = _run_twins(db)
        stop()
        assert n > 500
        assert counter["n"] <= 25  # was ~2000 (EXISTS + _find_open per finding); +1 MP-15, +3 MP-23, +1 mgmt twin

    def test_traffic_index_matches_query_path(self, db):
        rnd = random.Random(7)
        for _ in range(60):
            _session(db, rnd.choice([1, 2, 3, 4]), rnd.choice([1, 2, 3, 4]),
                     rnd.choice([None, 21, 23, 80, 502, 1500, 9999]),
                     rnd.choice(["tcp", "udp"]))
        idx = _TrafficIndex(db)
        for _ in range(300):
            src = set(rnd.sample([1, 2, 3, 4], rnd.randint(0, 2)))
            dst = set(rnd.sample([1, 2, 3, 4], rnd.randint(0, 2)))
            ports = rnd.choice([None, [], [23], [21, 80], [502, 9999]])
            ranges = rnd.choice([None, [(0, 65535)], [(1, 100)], [(1000, 2000), (9000, 9999)]])
            tr = rnd.choice([None, "tcp", "udp"])
            kw = dict(ports=ports, port_ranges=ranges, transport=tr)
            assert (_rule_traffic_confirmed(db, src, dst, **kw)
                    == _rule_traffic_confirmed(db, src, dst, _traffic=idx, **kw)), (src, dst, kw)


# ─── T3-19 one finding per logical rule, re-ingest stable ─────────────────────

SAMPLE = (Path(__file__).resolve().parent.parent / "sample_data"
          / "sample_fortigate_config.txt").read_text()
_POLICY7 = """config firewall policy
    edit 7
        set name "IT-to-PLC-Telnet"
        set srcintf "port3"
        set dstintf "port1"
        set srcaddr "all"
        set dstaddr "OT-PLCs"
        set service "TELNET" "HTTP"
        set action accept
    next
"""
CONFIG = SAMPLE.replace("config firewall policy\n", _POLICY7, 1)
TWINS_P7 = {"rule_cleartext_protocol", "rule_mgmt_protocol", "rule_cleartext_creds",
            "rule_mgmt_wrong_zone", "rule_it_ot_bypass"}


def _ingest(db):
    ingest_fortigate_config(CONFIG, db, firewall_name="FW-OT", generate_findings=False)
    for iface in db.query(FirewallInterface):
        iface.purdue_level = {"port1": 1, "port2": 3, "port3": 4}.get(iface.name)
    db.commit()


def _p7_findings(db, status="open"):
    return [f for f in db.query(Finding).filter(Finding.status == status,
                                                Finding.check_name.like("rule_%"))
            if (f.detail or {}).get("policy_id") == "7"]


class TestLogicalRuleGrouping:
    def test_address_group_policy_one_finding_per_check(self, db):
        _ingest(db)
        rows = db.query(FirewallRule).filter(FirewallRule.policy_id == "7").all()
        assert len(rows) == 4  # 2 PLC addresses x {TELNET, HTTP}
        run_periodic_reviews(db)
        fs = _p7_findings(db)
        assert sorted(f.check_name for f in fs) == sorted(TWINS_P7)  # exactly 1 each
        telnet = sorted(r.id for r in rows if r.dst_port == "23")
        for f in fs:
            # HTTP is not a management protocol: rule_mgmt_protocol lists the Telnet rows
            want = telnet if f.check_name == "rule_mgmt_protocol" else sorted(r.id for r in rows)
            assert sorted(f.detail["firewall_rule_ids"]) == want
            assert f.detail["expanded_rows"] == len(want)
            assert f.detail["rule_key"] == "7@fd%s" % rows[0].firewall_device_id
        ins = next(f for f in fs if f.check_name == "rule_cleartext_protocol")
        assert ins.detail["matched_ports"] == [23, 80]

    def test_reingest_creates_no_new_findings(self, db):
        _ingest(db)
        run_periodic_reviews(db)
        before = {(f.check_name, f.id, f.source_ref) for f in db.query(Finding)
                  if f.check_name.startswith("rule_")}
        _ingest(db)  # rows deleted + recreated
        stats = run_periodic_reviews(db)
        assert all(stats[k] == 0 for k in stats if k.startswith("review_rule_"))
        after = {(f.check_name, f.id, f.source_ref) for f in db.query(Finding)
                 if f.check_name.startswith("rule_")}
        assert after == before

    def test_raw_line_grouping_without_policy_id(self, db, fw):
        line = "access-list OUT extended permit tcp object-group IT object-group PLCS eq telnet"
        for dst in ("10.0.1.10", "10.0.1.11", "10.0.1.12"):
            _rule(db, fw, policy_id=None, dst=dst, raw_line=line)
        assert len(review_rule_cleartext_protocols(db)) == 1
        db.commit()
        # re-ingest: delete + recreate rows with new ids
        db.query(FirewallRule).delete()
        for dst in ("10.0.1.10", "10.0.1.11", "10.0.1.12"):
            _rule(db, fw, policy_id=None, dst=dst, raw_line=line)
        assert review_rule_cleartext_protocols(db) == []

    def test_disabled_rows_still_excluded(self, db, fw):
        _rule(db, fw, enabled=False)
        for fn in ae._RULE_TWIN_CHECKS:
            assert fn(db) == []

    def test_legacy_per_row_findings_superseded_not_deleted(self, db, fw):
        rows = [_rule(db, fw, dst=f"10.0.1.{i}") for i in (10, 11)]
        # Findings as the pre-T3-19 code wrote them: one per row, keyed on
        # firewall_rule_id.
        legacy = []
        for r in rows:
            ev = {**_rule_base_evidence(r, {3}, {1}), "matched_ports": [23]}
            legacy.append(_make_finding(db, "rule_cleartext_protocol", "old", "old", ev,
                                        firewall_rule_id=r.id, severity="medium"))
        db.commit()
        new = review_rule_cleartext_protocols(db)
        db.commit()
        assert len(new) == 1
        for f in legacy:
            db.refresh(f)
            assert f.status == "closed" and f.closed_at is not None
            assert f"#{new[0].id}" in f.notes
        assert db.query(Finding).filter(Finding.check_name == "rule_cleartext_protocol",
                                        Finding.status == "open").count() == 1
        assert db.query(Finding).count() == 3  # nothing deleted

    def test_other_checks_dedup_hash_unchanged(self):
        # Checks that never carry rule_key / baseline_id keep their hashes.
        ev = {"src_ip": "1.2.3.4", "dst_ip": "5.6.7.8", "dst_port": 23}
        assert _dedup_key("cleartext_creds", ev) == _dedup_key(
            "cleartext_creds", {**ev, "related_checks": ["x"], "firewall_rule_ids": [1]})


# ─── T3-20 related_checks + distinct titles ───────────────────────────────────

def test_related_checks_and_distinct_titles(db, fw):
    _rule(db, fw, "IT_ZONE", "port2", "23")  # IT L3 -> L1 Telnet
    run_periodic_reviews(db)
    fs = {f.check_name: f for f in db.query(Finding).filter(Finding.check_name.like("rule_%"))}
    assert set(fs) == TWINS_P7
    for name, f in fs.items():
        assert f.detail["related_checks"] == sorted(TWINS_P7 - {name})
    prefixes = {f.title.split(":")[0] for f in fs.values()}
    assert len(prefixes) == 5
    # related_checks is not part of the identity: a rerun does not duplicate
    stats = run_periodic_reviews(db)
    assert all(stats[k] == 0 for k in stats if k.startswith("review_rule_"))
    # and survives an escalation (post-pass re-applies it)
    _session(db, 3, 1, 23)
    db.commit()
    run_periodic_reviews(db)
    f = db.query(Finding).filter(Finding.check_name == "rule_cleartext_protocol").one()
    assert f.severity == "critical"
    assert f.detail["related_checks"] == sorted(TWINS_P7 - {"rule_cleartext_protocol"})


def test_standalone_twin_has_empty_related_checks(db, fw):
    _rule(db, fw, "IT_ZONE", "port2", "23")
    f = review_rule_mgmt_wrong_zone(db)[0]
    assert f.detail["related_checks"] == []


# ─── baseline port ranges (dst_port_end) ──────────────────────────────────────

class TestApprovedRanges:
    def _bl(self, db, *entries):
        b = _baseline(db)
        for lo, hi, proto in entries:
            db.add(ApprovedCommsEntry(baseline_id=b.id, src="10.0.0.0/8", dst="10.0.0.0/8",
                                      dst_port=lo, dst_port_end=hi, protocol=proto))
        db.flush()
        return b

    def test_high_port_range_covers_rule(self, db, fw):
        self._bl(db, (1024, 65535, "tcp"))
        _rule(db, fw, dst_port="1024-65535")
        _rule(db, fw, dst_port="gt 1023", policy_id="11")
        _rule(db, fw, dst_port="5000", policy_id="12")
        assert review_rule_conduit_drift(db) == []

    def test_range_partially_covers_any_rule(self, db, fw):
        self._bl(db, (1024, 65535, "tcp"), (502, None, "tcp"))
        _rule(db, fw, dst_port="any")
        f = review_rule_conduit_drift(db)[0]
        assert f.detail["uncovered_ports"] == "0-501,503-1023"

    def test_range_respects_transport(self, db, fw):
        self._bl(db, (1024, 65535, "udp"))
        _rule(db, fw, dst_port="5000", protocol="tcp")
        assert len(review_rule_conduit_drift(db)) == 1

    def test_reversed_end_treated_as_single_port(self, db, fw):
        self._bl(db, (5000, 10, "tcp"))
        _rule(db, fw, dst_port="5000-5001")
        assert review_rule_conduit_drift(db)[0].detail["uncovered_ports"] == "5001"


# ─── IPS check accepts kv (utm/ips) and CEF (ips) shapes ──────────────────────

@pytest.mark.parametrize("log_type,subtype,fires", [
    ("ips", None, True), ("utm", "ips", True), ("UTM", "IPS", True),
    ("utm", "virus", False), ("traffic", "ips", False),
])
def test_ips_check_log_shapes(db, log_type, subtype, fires):
    ev = FortiAnalyzerEvent(source_type="syslog_cef", log_type=log_type, subtype=subtype,
                            src_ip="10.3.0.5", dst_ip="10.1.0.9", attack_name="Modbus.Exploit",
                            device_name="fw1", received_at=_now(), raw_fields={})
    db.add(ev)
    db.flush()
    assert (ae.check_ips_ot_conduit(ev, db) is not None) == fires
