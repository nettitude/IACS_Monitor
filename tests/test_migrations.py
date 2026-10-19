"""
Alembic migration-chain tests (T1-02 / T1-03 / T1-05 / source_ref change).

Every test works on a throw-away SQLite file under a pytest tmp dir; the
project's own iasc_monitor.db is never touched.  Alembic is driven
in-process via ``alembic.command`` with the URL passed through
``Config.attributes["sqlalchemy.url"]`` (see alembic/env.py), except where a
fresh interpreter is needed (init_db binds its engine at import time; the
old-schema snapshot has its own ``app`` package).
"""
import os
import subprocess
import sys
import textwrap
from pathlib import Path

import pytest
import sqlalchemy as sa
from alembic import command
from alembic.autogenerate import compare_metadata
from alembic.config import Config
from alembic.runtime.migration import MigrationContext
from alembic.script import ScriptDirectory

from app.db import Base
import app.models  # noqa: F401  (registers every table on Base.metadata)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
ALEMBIC_INI = PROJECT_ROOT / "alembic.ini"

# Pre-remediation source tree (global UNIQUE on findings.source_ref, no
# nobaseline attestation index, dst_port String(32)).  Used to build a DB
# exactly as an existing installation's init_db()/create_all left it.
SNAPSHOT_DIR = Path(
    os.environ.get(
        "IACS_BASELINE_SNAPSHOT",
        "/tmp/claude-0/-home-claude/f4a41abe-6e15-5d22-88f6-4438a8b84543/scratchpad/baseline_snapshot",
    )
)

# autogenerate diffs that are deliberately ignored when comparing the migrated
# schema with Base.metadata.  Currently none on SQLite: the baseline and the
# idempotent revisions reproduce Base.metadata exactly.  (On PostgreSQL the GIN
# indexes created by a1b2c3d4e5f6 are not declared in the models and would
# show up as 'remove_index' - not exercised here, no PG server in CI.)
IGNORED_DIFFS: set = set()


def _cfg(url: str) -> Config:
    cfg = Config(str(ALEMBIC_INI))
    cfg.set_main_option("script_location", str(PROJECT_ROOT / "alembic"))
    cfg.attributes["sqlalchemy.url"] = url
    cfg.attributes["skip_logging_config"] = True
    return cfg


def _head() -> str:
    return ScriptDirectory.from_config(_cfg("sqlite://")).get_current_head()


def _current(url: str):
    eng = sa.create_engine(url)
    try:
        with eng.connect() as conn:
            return MigrationContext.configure(conn).get_current_heads()
    finally:
        eng.dispose()


def _schema_diffs(url: str) -> list:
    eng = sa.create_engine(url)
    try:
        with eng.connect() as conn:
            mc = MigrationContext.configure(conn, opts={"compare_type": True})
            diffs = compare_metadata(mc, Base.metadata)
    finally:
        eng.dispose()

    def _key(d):
        # d is a tuple ('add_index', Index) or a list of modify_* tuples
        if isinstance(d, list):
            d = d[0]
        obj = d[-1] if d[0] in ("add_table", "remove_table", "add_index", "remove_index") else d
        return (d[0], getattr(obj, "name", str(obj)))

    return [d for d in diffs if _key(d) not in IGNORED_DIFFS]


@pytest.fixture
def db_url(tmp_path):
    return f"sqlite:///{tmp_path / 'mig.db'}"


# ---------------------------------------------------------------------------

def test_single_linear_head():
    script = ScriptDirectory.from_config(_cfg("sqlite://"))
    assert len(script.get_heads()) == 1
    assert len(script.get_bases()) == 1
    assert script.get_bases()[0] == "0001baseline0"


def test_upgrade_head_on_empty_db(db_url):
    command.upgrade(_cfg(db_url), "head")
    assert _current(db_url) == (_head(),)
    eng = sa.create_engine(db_url)
    tables = set(sa.inspect(eng).get_table_names())
    eng.dispose()
    assert set(Base.metadata.tables) <= tables


def test_migrated_schema_matches_models(db_url):
    command.upgrade(_cfg(db_url), "head")
    diffs = _schema_diffs(db_url)
    assert diffs == [], f"schema drift between migrations and models: {diffs}"


def test_init_db_then_upgrade_is_noop(tmp_path):
    db_file = tmp_path / "init.db"
    url = f"sqlite:///{db_file}"
    env = dict(os.environ, IACS_DATABASE_URL=url)
    # Fresh interpreter: app.db binds its engine to IACS_DATABASE_URL at import.
    # Run from tmp_path to prove the alembic.ini lookup does not depend on CWD.
    subprocess.run(
        [sys.executable, "-c",
         f"import sys; sys.path.insert(0, {str(PROJECT_ROOT)!r}); "
         "from app.db import init_db; init_db()"],
        check=True, cwd=tmp_path, env=env, capture_output=True, text=True,
    )
    assert _current(url) == (_head(),), "init_db() must stamp a new database at head"
    # Would raise "table ... already exists" if init_db had not stamped.
    command.upgrade(_cfg(url), "head")
    assert _current(url) == (_head(),)
    assert _schema_diffs(url) == []


def test_downgrade_base_then_upgrade_head(db_url):
    cfg = _cfg(db_url)
    command.upgrade(cfg, "head")
    command.downgrade(cfg, "base")
    eng = sa.create_engine(db_url)
    leftover = set(sa.inspect(eng).get_table_names()) - {"alembic_version"}
    eng.dispose()
    assert leftover == set()
    command.upgrade(cfg, "head")
    assert _schema_diffs(db_url) == []


def test_offline_sql_render_postgresql():
    """`alembic upgrade head --sql` works for PostgreSQL and emits valid-looking
    partial-index predicates (T1-05: no 'IS 1' on a boolean)."""
    pytest.importorskip("psycopg2")
    proc = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(ALEMBIC_INI), "upgrade", "head", "--sql"],
        cwd=PROJECT_ROOT, capture_output=True, text=True,
        env=dict(os.environ, IACS_DATABASE_URL="postgresql+psycopg2://u:p@localhost/iasc"),
    )
    assert proc.returncode == 0, proc.stderr
    sql = proc.stdout
    assert "IS 1" not in sql
    assert "forti_analyzer_events" not in sql
    assert "WHERE is_current = true" in sql
    assert "ix_attestation_one_current_nobaseline" in sql
    assert "WHERE status = 'open'" in sql


# ---------------------------------------------------------------------------
# Upgrade of an existing pre-remediation database
# ---------------------------------------------------------------------------

def _build_old_schema_db(db_file: Path) -> None:
    code = textwrap.dedent(f"""
        import sys
        sys.path.insert(0, {str(SNAPSHOT_DIR)!r})
        import sqlalchemy as sa
        from app.db import Base
        import app.models
        assert app.models.__file__.startswith({str(SNAPSHOT_DIR)!r}), app.models.__file__
        eng = sa.create_engine({f"sqlite:///{db_file}"!r})
        Base.metadata.create_all(eng)
    """)
    subprocess.run(
        [sys.executable, "-c", code], check=True, cwd=db_file.parent,
        env={k: v for k, v in os.environ.items() if k != "IACS_DATABASE_URL"},
        capture_output=True, text=True,
    )


@pytest.mark.skipif(not (SNAPSHOT_DIR / "app" / "models.py").exists(),
                    reason="pre-remediation snapshot not available")
def test_upgrade_from_old_schema(tmp_path):
    db_file = tmp_path / "old.db"
    url = f"sqlite:///{db_file}"
    _build_old_schema_db(db_file)

    eng = sa.create_engine(url)
    # Sanity: the old schema really has the global UNIQUE on source_ref.
    ucs = sa.inspect(eng).get_unique_constraints("findings")
    assert any(uc["column_names"] == ["source_ref"] for uc in ucs)
    with eng.begin() as conn:
        conn.execute(sa.text(
            "INSERT INTO findings (category, severity, status, title, source_ref) "
            "VALUES ('real_time', 'high', 'closed', 'old closed', 'ref-1')"
        ))
        conn.execute(sa.text(
            "INSERT INTO firewall_rules (device_type, action, dst_port) "
            "VALUES ('fortigate', 'accept', '443')"
        ))
    eng.dispose()

    cfg = _cfg(url)
    command.stamp(cfg, "b2c3d4e5f6a7")
    command.upgrade(cfg, "head")
    assert _current(url) == (_head(),)
    assert _schema_diffs(url) == []

    eng = sa.create_engine(url)
    insp = sa.inspect(eng)
    assert not any(uc["column_names"] == ["source_ref"] for uc in insp.get_unique_constraints("findings"))
    ix = {i["name"]: i for i in insp.get_indexes("findings")}
    assert "ix_findings_source_ref" in ix and not ix["ix_findings_source_ref"]["unique"]
    assert ix["ux_findings_site_source_ref_open"]["unique"]   # per site since e1f2a3b4c5d6
    assert "ux_attestation_site_one_current_nobaseline" in {
        i["name"] for i in insp.get_indexes("attestations")}

    with eng.begin() as conn:
        # data survived the SQLite table rebuilds
        assert conn.execute(sa.text("SELECT count(*) FROM findings")).scalar() == 1
        assert conn.execute(sa.text("SELECT dst_port FROM firewall_rules")).scalar() == "443"
        # a closed + a new open finding with the same source_ref can coexist
        conn.execute(sa.text(
            "INSERT INTO findings (category, severity, status, title, source_ref, site_id) "
            "VALUES ('real_time', 'high', 'open', 'recurrence', 'ref-1', 1)"
        ))
    with pytest.raises(sa.exc.IntegrityError):
        with eng.begin() as conn:
            # ... but two open ones cannot
            conn.execute(sa.text(
                "INSERT INTO findings (category, severity, status, title, source_ref, site_id) "
                "VALUES ('real_time', 'high', 'open', 'dup', 'ref-1', 1)"
            ))
    with eng.begin() as conn:
        long_ports = ",".join(str(p) for p in range(1000, 1060))
        assert len(long_ports) > 32
        conn.execute(sa.text(
            "INSERT INTO firewall_rules (device_type, action, dst_port, site_id) "
            "VALUES ('fortigate', 'accept', :p, 1)"
        ), {"p": long_ports})
    eng.dispose()

    # And the chain is re-runnable: upgrading an at-head DB again is a no-op.
    command.upgrade(cfg, "head")


def test_nobaseline_duplicates_demoted_on_upgrade(tmp_path):
    """Pre-existing duplicate current NULL-baseline attestations are demoted
    (newest kept) so ix_attestation_one_current_nobaseline can be created."""
    url = f"sqlite:///{tmp_path / 'dup.db'}"
    cfg = _cfg(url)
    command.upgrade(cfg, "head")
    eng = sa.create_engine(url)
    with eng.begin() as conn:
        conn.execute(sa.text("DROP INDEX ux_attestation_site_one_current_nobaseline"))
        for i in range(3):
            conn.execute(sa.text(
                "INSERT INTO attestations (checklist_id, attested_by, attested_at, is_current, site_id) "
                "VALUES ('1.1', :who, '2026-01-01', 1, 1)"
            ), {"who": f"u{i}"})
    command.stamp(cfg, "b2c3d4e5f6a7")
    command.upgrade(cfg, "head")
    with eng.connect() as conn:
        rows = conn.execute(sa.text(
            "SELECT attested_by FROM attestations WHERE is_current = 1"
        )).fetchall()
    eng.dispose()
    assert [r[0] for r in rows] == ["u2"]


def test_unversioned_legacy_db_stamped_at_baseline_reconciles(tmp_path):
    """A create_all-era database with no alembic_version, columns the old
    migration chain never added, and duplicate OPEN findings (seen in a real
    deployment for cross_fw_* checks) must reach head via
    `stamp 0001baseline0` + `upgrade head` - the path install.sh, the Docker
    entrypoint and init_db's warning now use."""
    db_file = tmp_path / "legacy.db"
    url = f"sqlite:///{db_file}"
    eng = sa.create_engine(url)
    Base.metadata.create_all(eng)
    with eng.begin() as conn:
        # Simulate the legacy shape.
        conn.execute(sa.text("DROP INDEX ux_findings_site_source_ref_open"))
        conn.execute(sa.text("DROP INDEX ix_firewall_rule_order"))
        conn.execute(sa.text("ALTER TABLE firewall_rules DROP COLUMN rule_order"))
        conn.execute(sa.text("DROP INDEX ix_networksession_pcap_capture_id"))
        # (create_all at head already has sites/site_id; legacy site handling
        # is covered by test_pristine_legacy_db_upgrade_assigns_default_site)
        conn.execute(sa.text("INSERT INTO sites (id, name, code) VALUES (1, 'Default', 'default')"))
        for title in ("first", "second", "third"):
            conn.execute(sa.text(
                "INSERT INTO findings (category, severity, status, title, source_ref, site_id) "
                "VALUES ('periodic_review', 'high', 'open', :t, 'cross_fw_no_rules:1-2', 1)"
            ), {"t": title})
        conn.execute(sa.text(
            "INSERT INTO findings (category, severity, status, title, source_ref, site_id) "
            "VALUES ('periodic_review', 'low', 'open', 'unique one', 'other-ref', 1)"
        ))
    assert "alembic_version" not in sa.inspect(eng).get_table_names()
    eng.dispose()

    cfg = _cfg(url)
    command.stamp(cfg, "0001baseline0")
    command.upgrade(cfg, "head")
    assert _current(url) == (_head(),)

    # Only SQLite-inert differences may remain: FKs on columns added via
    # ALTER TABLE (SQLite can't add them in place; not enforced there).
    leftover = [d for d in _schema_diffs(url) if not (isinstance(d, tuple) and d[0] == "add_fk")]
    assert leftover == []

    eng = sa.create_engine(url)
    with eng.connect() as conn:
        rows = conn.execute(sa.text(
            "SELECT title, status, notes FROM findings "
            "WHERE source_ref = 'cross_fw_no_rules:1-2' ORDER BY id"
        )).all()
        assert [r.status for r in rows] == ["open", "closed", "closed"]
        assert rows[0].title == "first"                       # oldest kept open
        assert all("c3d4e5f6a7b8" in (r.notes or "") for r in rows[1:])
        assert conn.execute(sa.text(
            "SELECT status FROM findings WHERE source_ref='other-ref'")).scalar() == "open"
        assert "rule_order" in {c["name"] for c in sa.inspect(conn).get_columns("firewall_rules")}
    eng.dispose()


# ---------------------------------------------------------------------------
# f6a7b8c9d0e1 (T3 API/DB robustness)
# ---------------------------------------------------------------------------

def test_duplicate_sessions_merged_before_unique_5tuple(tmp_path):
    """Legacy duplicate 5-tuple sessions are merged (lowest id kept, counters
    summed, first/last_seen min/max, details + findings re-pointed) and then
    ux_session_5tuple is created; NULL-port sessions are left alone."""
    url = f"sqlite:///{tmp_path / 'sess.db'}"
    cfg = _cfg(url)
    command.upgrade(cfg, "head")
    eng = sa.create_engine(url)
    with eng.begin() as conn:
        conn.execute(sa.text("DROP INDEX ux_session_5tuple"))
        conn.execute(sa.text(
            "CREATE INDEX ix_session_5tuple ON network_sessions "
            "(src_host_id, dst_host_id, src_port, dst_port, transport)"))
        conn.execute(sa.text("INSERT INTO hosts (id, ip, site_id) VALUES (1, '10.0.0.1', 1), (2, '10.0.0.2', 1)"))
        rows = [
            # id, sport, dport, transport, proto, pkts, bytes, first, last
            (10, 1000, 502, "tcp", "unknown", 5, 500, "2026-01-02 00:00:00", "2026-01-03 00:00:00"),
            (11, 1000, 502, "tcp", "modbus", 7, 700, "2026-01-01 00:00:00", "2026-01-02 00:00:00"),
            (12, 1000, 502, "tcp", "unknown", 1, 100, "2026-01-05 00:00:00", "2026-01-09 00:00:00"),
            (13, 2000, 502, "tcp", "modbus", 2, 200, "2026-01-01 00:00:00", "2026-01-01 00:00:00"),
            (14, None, None, "ethernet", "profinet", 1, 60, "2026-01-01 00:00:00", "2026-01-01 00:00:00"),
            (15, None, None, "ethernet", "profinet", 1, 60, "2026-01-01 00:00:00", "2026-01-01 00:00:00"),
        ]
        for r in rows:
            conn.execute(sa.text(
                "INSERT INTO network_sessions (id, src_host_id, dst_host_id, src_port, dst_port, "
                "transport, protocol, packet_count, byte_count, first_seen, last_seen) "
                "VALUES (:id, 1, 2, :sp, :dp, :t, :p, :pk, :b, :f, :l)"),
                dict(zip(["id", "sp", "dp", "t", "p", "pk", "b", "f", "l"], r)))
        for sid in (10, 11, 12, 12, 13):
            conn.execute(sa.text(
                "INSERT INTO protocol_details (session_id, protocol) VALUES (:s, 'modbus')"), {"s": sid})
        conn.execute(sa.text(
            "INSERT INTO findings (category, severity, status, title, session_id, site_id) "
            "VALUES ('real_time', 'low', 'open', 'f', 12, 1)"))
    command.stamp(cfg, "e5f6a7b8c9d0")
    command.upgrade(cfg, "head")
    assert _schema_diffs(url) == []

    with eng.connect() as conn:
        sess = {r.id: r for r in conn.execute(sa.text(
            "SELECT * FROM network_sessions ORDER BY id")).all()}
        assert sorted(sess) == [10, 13, 14, 15]
        s10 = sess[10]
        assert (s10.packet_count, s10.byte_count) == (13, 1300)
        assert str(s10.first_seen).startswith("2026-01-01")
        assert str(s10.last_seen).startswith("2026-01-09")
        assert s10.protocol == "modbus"
        assert sess[13].packet_count == 2
        details = conn.execute(sa.text(
            "SELECT session_id, count(*) FROM protocol_details GROUP BY session_id")).all()
        assert dict(details) == {10: 4, 13: 1}
        assert conn.execute(sa.text("SELECT session_id FROM findings")).scalar() == 10
        assert "_iasc_session_merge" not in sa.inspect(conn).get_table_names()
    ix = {i["name"]: i for i in sa.inspect(eng).get_indexes("network_sessions")}
    assert ix["ux_session_5tuple"]["unique"] and "ix_session_5tuple" not in ix
    with pytest.raises(sa.exc.IntegrityError):
        with eng.begin() as conn:
            conn.execute(sa.text(
                "INSERT INTO network_sessions (src_host_id, dst_host_id, src_port, dst_port, "
                "transport, protocol) VALUES (1, 2, 1000, 502, 'tcp', 'x')"))
    eng.dispose()
    command.upgrade(cfg, "head")  # re-runnable


def test_rule_fk_set_null_after_upgrade(tmp_path):
    """findings.rule_id gets ON DELETE SET NULL (rebuilt from a DB at the
    previous revision whose FK had no ondelete)."""
    url = f"sqlite:///{tmp_path / 'fk.db'}"
    cfg = _cfg(url)
    command.upgrade(cfg, "e5f6a7b8c9d0")
    eng = sa.create_engine(url)
    fk = [f for f in sa.inspect(eng).get_foreign_keys("findings") if f["constrained_columns"] == ["rule_id"]]
    assert not fk[0]["options"].get("ondelete")
    with eng.begin() as conn:
        conn.execute(sa.text("INSERT INTO firewall_rules (id, device_type, action) VALUES (5, 'x', 'accept')"))
        conn.execute(sa.text(
            "INSERT INTO findings (category, severity, status, title, rule_id) "
            "VALUES ('config_review', 'low', 'open', 'keep me', 5)"))
    eng.dispose()
    command.upgrade(cfg, "head")
    eng = sa.create_engine(url)
    fk = [f for f in sa.inspect(eng).get_foreign_keys("findings") if f["constrained_columns"] == ["rule_id"]]
    assert fk[0]["options"]["ondelete"] == "SET NULL"
    with eng.begin() as conn:
        conn.exec_driver_sql("PRAGMA foreign_keys=ON")
        conn.execute(sa.text("DELETE FROM firewall_rules WHERE id = 5"))
        row = conn.execute(sa.text("SELECT title, rule_id FROM findings")).one()
    assert row.title == "keep me" and row.rule_id is None
    eng.dispose()


def test_offline_sql_render_postgresql_t3_ddl():
    pytest.importorskip("psycopg2")
    proc = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(ALEMBIC_INI), "upgrade", "head", "--sql"],
        cwd=PROJECT_ROOT, capture_output=True, text=True,
        env=dict(os.environ, IACS_DATABASE_URL="postgresql+psycopg2://u:p@localhost/iasc"),
    )
    assert proc.returncode == 0, proc.stderr
    sql = proc.stdout.split("Running upgrade e5f6a7b8c9d0 -> f6a7b8c9d0e1", 1)[1]
    for frag in (
        "ALTER TABLE approved_comms ADD COLUMN IF NOT EXISTS dst_port_end INTEGER",
        "ALTER TABLE fortiana_events ADD COLUMN IF NOT EXISTS dedup_hash VARCHAR(40)",
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_fortiana_events_dedup_hash ON fortiana_events (dedup_hash)",
        "CREATE INDEX IF NOT EXISTS ix_protocol_details_session_id ON protocol_details (session_id)",
        "CREATE INDEX IF NOT EXISTS ix_network_sessions_dst_host_id",
        "CREATE INDEX IF NOT EXISTS ix_hosts_last_seen ON hosts (last_seen)",
        "CREATE INDEX IF NOT EXISTS ix_network_sessions_last_seen",
        "CREATE TABLE _iasc_session_merge AS",
        "UPDATE protocol_details SET session_id",
        "UPDATE findings SET session_id",
        "CREATE UNIQUE INDEX IF NOT EXISTS ux_session_5tuple ON network_sessions "
        "(src_host_id, dst_host_id, src_port, dst_port, transport)",
        "DROP INDEX IF EXISTS ix_session_5tuple",
        "DROP CONSTRAINT IF EXISTS findings_rule_id_fkey",
        "FOREIGN KEY(rule_id) REFERENCES firewall_rules (id) ON DELETE SET NULL",
    ):
        assert frag in sql, frag
    # merge happens before the unique index is built
    assert sql.index("DELETE FROM network_sessions") < sql.index("ux_session_5tuple")


# ---------------------------------------------------------------------------
# b9c0d1e2f3a4 (F-08: Purdue L3.5 industrial DMZ)
# Data-carrying upgrade/downgrade is covered in tests/test_purdue_dmz.py.
# ---------------------------------------------------------------------------

_PURDUE_COLUMNS = {
    "hosts": {"purdue_level": "ck_host_purdue_level_valid"},
    "firewall_devices": {"purdue_zone_from": "ck_fw_device_zone_from_purdue",
                         "purdue_zone_to": "ck_fw_device_zone_to_purdue"},
    "firewalls": {"purdue_level_ingress": "ck_firewall_ingress_purdue",
                  "purdue_level_egress": "ck_firewall_egress_purdue"},
    "firewall_interfaces": {"purdue_level": "ck_fw_iface_purdue_level",
                            "suggested_purdue_level": "ck_fw_iface_suggested_purdue"},
    "switch_vlans": {"purdue_level": "ck_switch_vlan_purdue_level"},
}


def test_purdue_level_columns_numeric_with_checks_after_upgrade(db_url):
    """Fresh upgrade: every Purdue level column is NUMERIC(2,1) with its
    named CHECK (compare_metadata does not compare CHECK constraints, so
    they are asserted here), and the pre-F-08 0-5 range CHECK is gone."""
    command.upgrade(_cfg(db_url), "head")
    eng = sa.create_engine(db_url)
    insp = sa.inspect(eng)
    for table, cols in _PURDUE_COLUMNS.items():
        types = {c["name"]: c["type"] for c in insp.get_columns(table)}
        cks = {ck["name"]: ck["sqltext"] for ck in insp.get_check_constraints(table)}
        for col, ck in cols.items():
            assert isinstance(types[col], sa.Numeric) and not isinstance(types[col], sa.Float)
            assert (types[col].precision, types[col].scale) == (2, 1), (table, col)
            assert ck in cks and "3.5" in cks[ck], (table, ck)
    assert "ck_host_purdue_level_range" not in {
        ck["name"] for ck in insp.get_check_constraints("hosts")}
    eng.dispose()
    command.upgrade(_cfg(db_url), "head")  # re-runnable


def test_offline_sql_render_postgresql_purdue_dmz():
    pytest.importorskip("psycopg2")
    proc = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(ALEMBIC_INI), "upgrade", "head", "--sql"],
        cwd=PROJECT_ROOT, capture_output=True, text=True,
        env=dict(os.environ, IACS_DATABASE_URL="postgresql+psycopg2://u:p@localhost/iasc"),
    )
    assert proc.returncode == 0, proc.stderr
    sql = proc.stdout.split("Running upgrade a8b9c0d1e2f3 -> b9c0d1e2f3a4", 1)[1]
    assert "ALTER TABLE hosts DROP CONSTRAINT IF EXISTS ck_host_purdue_level_range" in sql
    for table, cols in _PURDUE_COLUMNS.items():
        for col, ck in cols.items():
            assert f"ALTER TABLE {table} ALTER COLUMN {col} TYPE NUMERIC(2, 1)" in sql
            assert f"ALTER TABLE {table} DROP CONSTRAINT IF EXISTS {ck}" in sql
            assert (f"ALTER TABLE {table} ADD CONSTRAINT {ck} CHECK "
                    f"({col} IS NULL OR {col} IN (0, 1, 2, 3, 3.5, 4, 5))") in sql
    # each DROP ... IF EXISTS precedes its ADD, so the script is re-runnable
    assert sql.index("DROP CONSTRAINT IF EXISTS ck_host_purdue_level_valid") \
        < sql.index("ADD CONSTRAINT ck_host_purdue_level_valid")


def test_offline_sql_render_sqlite_purdue_dmz_is_comment_only():
    proc = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(ALEMBIC_INI), "upgrade",
         "a8b9c0d1e2f3:b9c0d1e2f3a4", "--sql"],
        cwd=PROJECT_ROOT, capture_output=True, text=True,
        env=dict(os.environ, IACS_DATABASE_URL="sqlite:///offline-render-only.db"),
    )
    assert proc.returncode == 0, proc.stderr
    assert "require an online upgrade on SQLite" in proc.stdout
    assert "ALTER TABLE" not in proc.stdout.split("Running upgrade a8b9c0d1e2f3 -> b9c0d1e2f3a4", 1)[1]


# ---------------------------------------------------------------------------
# c0d1e2f3a4b5 (multi-site phase 1: sites, Default site, site_id on roots)
# ---------------------------------------------------------------------------

_SITE_TABLES = (
    "baselines", "firewalls", "firewall_devices", "firewall_rules", "nat_rules",
    "firewall_zones", "hosts", "pcap_captures", "fortiana_events", "findings",
    "attestations", "switch_interfaces", "switch_vlans", "mac_table_entries",
)
PRISTINE_DB = Path(os.environ.get("IACS_PRISTINE_DB", "/tmp/claude-0/pristine_original.db"))


def test_site_tables_match_models():
    """The migration's hand-kept table list equals the SiteScoped models."""
    # site_devices (phase 3) has a site_id too but is the device registry,
    # created by f1a2b3c4d5e6 - not a root table of c0d1e2f3a4b5; likewise
    # access_path_tag / access_path_hop, created with their site_id by
    # f7a8b9c0d1e2 / a9b0c1d2e3f4; firewall_groups by c1d2e3f4a5b6;
    # management_networks by d2e3f4a5b6c7; vpn_user_groups by a6b7c8d9e0f1;
    # connection_attempts by 7c8d9e0f1a2b (FO-04); subnet_zones by 9e0f1a2b3c4d (RS G3);
    # observed_names / external_flow_reviews by 1f2a3b4c5d6e (G5);
    # iec_zones / iec_zone_members / iec_conduits by 3b4c5d6e7f8a;
    # inventory_import_mappings by 8a9b0c1d2e3f; check_evaluations by 9b0c1d2e3f4a;
    # iec_conduit_rules by ac1d2e3f4a5b; report_check_exclusions by bd2e3f4a5b6c;
    # firewall_config_texts by ce3f4a5b6c7d; report_details by f8a9b0c1d2e3.
    assert set(_SITE_TABLES) == {t.name for t in Base.metadata.sorted_tables
                                 if "site_id" in t.c} - {"site_devices", "access_path_tag",
                                                                  "access_path_hop", "firewall_groups",
                                                                  "management_networks",
                                                                  "vpn_user_groups", "connection_attempts",
                                                                  "subnet_zones", "observed_names",
                                                                  "external_flow_reviews", "iec_zones",
                                                                  "iec_zone_members", "iec_conduits",
                                                                  "inventory_import_mappings",
                                                                  "check_evaluations", "iec_conduit_rules",
                                                                  "report_check_exclusions",
                                                                  "firewall_config_texts", "report_details"}


def _assert_site_columns(url: str, expect_default: bool = True) -> None:
    eng = sa.create_engine(url)
    insp = sa.inspect(eng)
    for table in _SITE_TABLES:
        col = {c["name"]: c for c in insp.get_columns(table)}["site_id"]
        assert col["nullable"] is False, table
        assert f"ix_{table}_site_id" in {i["name"] for i in insp.get_indexes(table)}, table
        assert any(fk["constrained_columns"] == ["site_id"] and fk["referred_table"] == "sites"
                   for fk in insp.get_foreign_keys(table)), table
    if expect_default:
        with eng.connect() as conn:
            assert conn.execute(sa.text(
                "SELECT name, code FROM sites WHERE code = 'default'")).one() == ("Default", "default")
    eng.dispose()


def test_fresh_upgrade_has_no_site_and_not_null_site_ids(db_url):
    """FI-01: a fresh install starts with no site at all (the operator creates
    the first one); the site columns and constraints are in place."""
    command.upgrade(_cfg(db_url), "head")
    _assert_site_columns(db_url, expect_default=False)
    assert _schema_diffs(db_url) == []
    command.upgrade(_cfg(db_url), "head")  # re-runnable
    eng = sa.create_engine(db_url)
    with eng.connect() as conn:
        assert conn.execute(sa.text("SELECT count(*) FROM sites")).scalar() == 0
    eng.dispose()


# Pre-existing SQLite-inert differences on the pristine legacy database that
# are unrelated to sites: FKs on columns reconcile added with ALTER TABLE
# (SQLite can't add them in place) and VARCHAR(n) -> TEXT (SQLite ignores
# VARCHAR lengths; only PostgreSQL is widened by d4e5f6a7b8c9).
def _site_or_unexpected_diffs(url: str) -> list:
    out = []
    for d in _schema_diffs(url):
        first = d[0] if isinstance(d, list) else d
        if first[0] == "add_fk" and "site_id" not in str(list(first[1].columns.keys())):
            continue
        if first[0] == "modify_type" and isinstance(first[-1], sa.Text):
            continue
        out.append(d)
    return out


@pytest.mark.skipif(not PRISTINE_DB.exists(), reason="pristine legacy DB not available")
@pytest.mark.parametrize("stamp", ["0001baseline0", "b2c3d4e5f6a7"])
def test_pristine_legacy_db_upgrade_assigns_default_site(tmp_path, stamp):
    """A real pre-sites database (rows in findings/firewalls/hosts/rules/
    zones/interfaces): every existing root row lands in the Default site.
    Upgrading runs d4e5f6a7b8c9 (reconcile) first, which already creates
    `sites` and adds the site_id columns NULLable from the live models; the
    site revision must backfill and tighten them anyway."""
    import shutil
    db_file = tmp_path / "pristine.db"
    shutil.copy(PRISTINE_DB, db_file)
    url = f"sqlite:///{db_file}"
    eng = sa.create_engine(url)
    with eng.connect() as conn:
        before = {t: conn.execute(sa.text(f"SELECT count(*) FROM {t}")).scalar()
                  for t in _SITE_TABLES if sa.inspect(conn).has_table(t)}
    eng.dispose()
    assert sum(before.values()) > 0

    cfg = _cfg(url)
    command.stamp(cfg, stamp)
    command.upgrade(cfg, "head")
    assert _current(url) == (_head(),)
    _assert_site_columns(url)
    assert _site_or_unexpected_diffs(url) == []

    eng = sa.create_engine(url)
    with eng.connect() as conn:
        default_id = conn.execute(sa.text("SELECT id FROM sites WHERE code='default'")).scalar()
        for table, n in before.items():
            assert conn.execute(sa.text(f"SELECT count(*) FROM {table}")).scalar() == n, table
            assert conn.execute(sa.text(
                f"SELECT count(*) FROM {table} WHERE site_id = :d"), {"d": default_id}).scalar() == n, table
    eng.dispose()
    command.upgrade(cfg, "head")  # re-runnable


def test_site_revision_tolerates_reconcile_added_columns(tmp_path):
    """The reconcile ordering: building a DB up to b9c0d1e2f3a4 runs
    d4e5f6a7b8c9 against the LIVE models, which creates an EMPTY `sites`
    table and adds every site_id column NULLable.  Rows written in that
    state have site_id NULL; c0d1e2f3a4b5 must insert Default, backfill and
    tighten."""
    url = f"sqlite:///{tmp_path / 'rec.db'}"
    cfg = _cfg(url)
    command.upgrade(cfg, "b9c0d1e2f3a4")
    eng = sa.create_engine(url)
    insp = sa.inspect(eng)
    assert insp.has_table("sites")
    assert {c["name"]: c for c in insp.get_columns("hosts")}["site_id"]["nullable"] is True
    with eng.begin() as conn:
        assert conn.execute(sa.text("SELECT count(*) FROM sites")).scalar() == 0
        conn.execute(sa.text("INSERT INTO hosts (ip) VALUES ('10.9.9.9')"))
        conn.execute(sa.text("INSERT INTO firewalls (name, vendor, topology_confirmed, is_multi_fw) "
                             "VALUES ('fw', 'fortigate', 0, 0)"))
    eng.dispose()
    command.upgrade(cfg, "head")
    _assert_site_columns(url)
    assert _schema_diffs(url) == []
    eng = sa.create_engine(url)
    with eng.connect() as conn:
        assert conn.execute(sa.text("SELECT site_id FROM hosts")).scalar() == 1
        assert conn.execute(sa.text("SELECT site_id FROM firewalls")).scalar() == 1
    eng.dispose()


def test_offline_sql_render_postgresql_sites():
    pytest.importorskip("psycopg2")
    proc = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(ALEMBIC_INI), "upgrade", "head", "--sql"],
        cwd=PROJECT_ROOT, capture_output=True, text=True,
        env=dict(os.environ, IACS_DATABASE_URL="postgresql+psycopg2://u:p@localhost/iasc"),
    )
    assert proc.returncode == 0, proc.stderr
    sql = proc.stdout.split("Running upgrade b9c0d1e2f3a4 -> c0d1e2f3a4b5", 1)[1]
    assert "CREATE TABLE IF NOT EXISTS sites" in sql
    assert "CREATE UNIQUE INDEX IF NOT EXISTS ux_sites_code ON sites (code)" in sql
    assert "SELECT 'Default', 'default'" in sql
    for t in _SITE_TABLES:
        add = sql.index(f"ALTER TABLE {t} ADD COLUMN IF NOT EXISTS site_id INTEGER")
        fill = sql.index(f"UPDATE {t} SET site_id = (SELECT MIN(id) FROM sites")
        nn = sql.index(f"ALTER TABLE {t} ALTER COLUMN site_id SET NOT NULL")
        assert add < fill < nn, t
        assert (f"ALTER TABLE {t} ADD CONSTRAINT {t}_site_id_fkey FOREIGN KEY(site_id) "
                "REFERENCES sites (id)") in sql
        assert f"CREATE INDEX IF NOT EXISTS ix_{t}_site_id ON {t} (site_id)" in sql
    # downgrade renders too
    proc = subprocess.run(
        [sys.executable, "-m", "alembic", "-c", str(ALEMBIC_INI), "downgrade",
         "c0d1e2f3a4b5:b9c0d1e2f3a4", "--sql"],
        cwd=PROJECT_ROOT, capture_output=True, text=True,
        env=dict(os.environ, IACS_DATABASE_URL="postgresql+psycopg2://u:p@localhost/iasc"),
    )
    assert proc.returncode == 0, proc.stderr
    assert "DROP TABLE IF EXISTS sites" in proc.stdout
