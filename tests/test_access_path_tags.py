"""
Access-path review, wave 1 of phases 3+4 (docs/access-path-review.md):

* status rename: ``traffic`` = seen / not_seen / no_capture / partial,
  ``capture_window``, ``rule_hits_since``;
* ``access_path_tag`` storage with stable ``tag_key`` values;
* tags merged into GET /access-paths (report_include default / override,
  orphaned tags, classification / report_include filters);
* POST /access-paths/classify (bulk upsert, validation, site isolation,
  findings-sync hook);
* the f7a8b9c0d1e2 migration (fresh drift, PostgreSQL offline render).

Built on the PLANT1-FGT tabletop scenario (tests/test_access_paths.py).
"""
import os
import re
import subprocess
import sys
from datetime import timedelta
from pathlib import Path

import pytest
import sqlalchemy as sa

from app.models import (
    AccessPathTag, Firewall, FirewallDevice, FirewallInterface, FirewallRule,
    FirewallZoneDef, NatRule,
)
from app.parsers import access_paths as ap
from app.parsers.access_paths import (
    ClassifyError, classify_access_paths, enumerate_access_paths,
)
from tests.test_access_paths import (  # noqa: F401  (db fixture re-used)
    PLANT1_CFG, PLANT1_LEVELS, _ingest, _site, db,
)
from tests.test_access_paths_overlay import (
    FIELD, HISTORIAN, PLC, RELAY, T0, _event, _host, _plant, _sess, HOST_LEVELS,
)

PROJECT_ROOT = Path(__file__).resolve().parent.parent
HEX16 = r"[0-9a-f]{16}"


def _row(paths, pid):
    rows = [p for p in paths if p["direction"] != "composed"
            and [c["policy_id"] for c in p["chain"]] == [pid]]
    assert len(rows) == 1, (pid, rows)
    return rows[0]


def _composed(paths):
    rows = [p for p in paths if p["direction"] == "composed"]
    assert len(rows) == 1
    return rows[0]


def _get(db, sid, **kw):
    return enumerate_access_paths(db, sid, **kw)


def _classify(db, sid, items):
    res = classify_access_paths(db, sid, items)
    db.commit()
    return res


# ================================================================ rename ==
def test_traffic_field_statuses_and_capture_window(db):
    sid, h = _plant(db)
    out = _get(db, sid)
    row = _row(out["paths"], "6")
    assert "observed" not in row
    assert row["traffic"]["status"] == "no_capture"
    assert out["capture_window"] == {"first": None, "last": None}

    _sess(db, h[HISTORIAN], h[PLC], 40000, 502, seen=T0)
    _sess(db, h[RELAY], h[PLC], 40001, 502, seen=T0 + timedelta(hours=3))
    _event(db, sid, "1", ts=T0 - timedelta(days=2))
    _event(db, sid, "1", ts=T0 - timedelta(days=1))
    db.commit()
    out = _get(db, sid)
    win = out["capture_window"]
    assert win["first"].startswith("2026-10-01T12:00") and win["last"].startswith("2026-10-01T15:00")
    assert _row(out["paths"], "6")["traffic"]["status"] == "seen"
    not_seen = _row(out["paths"], "9")["traffic"]
    assert not_seen["status"] == "not_seen"
    assert not_seen["capture_window"] == win       # "not seen in <window>"
    hist = _row(out["paths"], "1")["traffic"]
    assert hist["rule_hits"] == 2
    assert hist["rule_hits_since"].startswith("2026-09-29T12:00")   # earliest counted hit
    assert hist["last_matched"].startswith("2026-09-30T12:00")
    assert set(out["counts"]["by_traffic"]) == {"seen", "not_seen", "no_capture", "partial"}


# ============================================================== tag keys ==
def test_tag_key_formats_and_uniqueness(db):
    sid, h = _plant(db)
    _sess(db, h[HISTORIAN], h[FIELD], 41000, 502)        # unexplained L4 -> L0
    db.commit()
    out = _get(db, sid)
    assert re.fullmatch(rf"p:PLANT1-FGT:-:6:{HEX16}", _row(out["paths"], "6")["tag_key"])
    assert re.fullmatch(rf"c:{HEX16}", _composed(out["paths"])["tag_key"])
    flow = out["unmatched_observed"][0]
    assert re.fullmatch(rf"u:{HEX16}", flow["tag_key"])
    keys = [p["tag_key"] for p in out["paths"]] + [f["tag_key"] for f in out["unmatched_observed"]]
    assert len(keys) == len(set(keys))
    # the documented hashes
    assert flow["tag_key"] == "u:" + ap._h16(f"{HISTORIAN}|{FIELD}|tcp|502")


def _spacer(db, rule_id=None, fw_id=None):
    """Rows with high ids in another site, so ids allocated next differ from
    the deleted ones (SQLite reuses the maximum id after a delete)."""
    other = _site(db, "Spacer")
    if fw_id is not None:
        db.add(Firewall(id=fw_id, name="SPACER", vendor="fortigate", site_id=other))
    if rule_id is not None:
        db.add(FirewallRule(id=rule_id, device_type="fortigate", action="deny", site_id=other))
    db.commit()


def test_tag_key_stable_across_config_reingest(db):
    sid, _h = _plant(db)
    key = _row(_get(db, sid)["paths"], "6")["tag_key"]
    _classify(db, sid, [{"tag_key": key, "classification": "it_ot_bypass", "note": "direct"}])
    old_ids = {r.id for r in db.query(FirewallRule).filter(FirewallRule.site_id == sid)}
    _spacer(db, rule_id=1000)
    _ingest(db, PLANT1_CFG, "PLANT1-FGT", sid, PLANT1_LEVELS)       # same config again
    new_ids = {r.id for r in db.query(FirewallRule).filter(FirewallRule.site_id == sid)}
    assert new_ids and new_ids != old_ids              # rule rows really were replaced
    row = _row(_get(db, sid)["paths"], "6")
    assert row["tag_key"] == key
    assert row["classification"] == "it_ot_bypass" and row["note"] == "direct"


def _delete_firewall(db, fw):
    for model in (FirewallRule, NatRule, FirewallZoneDef, FirewallInterface, FirewallDevice):
        db.query(model).filter(model.firewall_id == fw.id).delete(synchronize_session=False)
    db.delete(fw)
    db.commit()


def test_tag_key_stable_across_firewall_delete_and_readd(db):
    sid, _h = _plant(db)
    key = _row(_get(db, sid)["paths"], "6")["tag_key"]
    _classify(db, sid, [{"tag_key": key, "classification": "permissive"}])
    fw = db.query(Firewall).filter(Firewall.site_id == sid, Firewall.name == "PLANT1-FGT").one()
    old_id = fw.id
    _delete_firewall(db, fw)
    _spacer(db, fw_id=1000, rule_id=1000)
    assert _get(db, sid)["orphaned_tags"][0]["tag_key"] == key       # gone for now
    fw2 = _ingest(db, PLANT1_CFG, "PLANT1-FGT", sid, PLANT1_LEVELS)
    assert fw2.id != old_id
    out = _get(db, sid)
    assert _row(out["paths"], "6")["classification"] == "permissive"
    assert out["orphaned_tags"] == [] and out["counts"]["orphaned"] == 0


# ======================================================== upsert / defaults ==
def test_upsert_updates_one_row_and_leaves_omitted_fields(db):
    sid, _h = _plant(db)
    key = _row(_get(db, sid)["paths"], "6")["tag_key"]
    _classify(db, sid, [{"tag_key": key, "classification": "permissive", "note": "n1",
                         "classified_by": "alice"}])
    first = db.query(AccessPathTag).one()
    stamped = first.classified_at
    assert (first.kind, first.policy_id, first.vdom) == ("path", "6", None)
    assert first.firewall_device_id is not None
    _classify(db, sid, [{"tag_key": key, "note": "n2"}])       # note only
    db.expire_all()
    tag = db.query(AccessPathTag).one()
    assert tag.classification == "permissive" and tag.note == "n2"
    assert tag.classified_by == "alice" and tag.classified_at == stamped
    _classify(db, sid, [{"tag_key": key, "classification": "exception", "classified_by": "bob"}])
    db.expire_all()
    tag = db.query(AccessPathTag).one()
    assert (tag.classification, tag.classified_by) == ("exception", "bob")
    assert db.query(AccessPathTag).count() == 1


def test_report_include_default_override_and_null_reset(db):
    sid, _h = _plant(db)
    paths = _get(db, sid)["paths"]
    flagged, plain = _row(paths, "6"), _row(paths, "1")
    assert flagged["flags"] and flagged["report_include_default"] is True
    assert flagged["report_include"] is True and flagged["classification"] == "unclassified"
    assert not plain["flags"] and plain["report_include"] is False
    key = flagged["tag_key"]

    item = _classify(db, sid, [{"tag_key": key, "classification": "reviewed_ok"}])["items"][0]
    assert item["report_include_default"] is False and item["report_include"] is False
    item = _classify(db, sid, [{"tag_key": key, "report_include": True}])["items"][0]
    assert item["report_include"] is True and item["report_include_default"] is False
    item = _classify(db, sid, [{"tag_key": key, "report_include": None}])["items"][0]
    assert item["report_include"] is False                       # back to the default
    assert db.query(AccessPathTag).one().report_include is None
    item = _classify(db, sid, [{"tag_key": plain["tag_key"], "report_include": True}])["items"][0]
    assert item["report_include"] is True and item["report_include_default"] is False


# ============================================================= validation ==
def test_unknown_key_rejects_whole_request(db):
    sid, _h = _plant(db)
    key = _row(_get(db, sid)["paths"], "6")["tag_key"]
    with pytest.raises(ClassifyError, match="unknown tag_key"):
        classify_access_paths(db, sid, [{"tag_key": key, "classification": "permissive"},
                                        {"tag_key": "p:PLANT1-FGT:-:6:0000000000000000"}])
    db.rollback()
    assert db.query(AccessPathTag).count() == 0


@pytest.mark.parametrize("items, msg", [
    ([], "non-empty"),
    ([{"tag_key": "k"}] * 2, "listed twice"),
    ([{"tag_key": "k", "classification": "bad"}], "classification must be"),
    ([{"tag_key": "k", "report_include": "yes"}], "report_include"),
    ([{"tag_key": "k", "note": "x" * 2001}], "2000"),
    ([{"tag_key": "k", "classified_by": "x" * 129}], "128"),
    ([{"tag_key": "k", "colour": "red"}], "unknown field"),
    ([{"tag_key": f"k{i}"} for i in range(501)], "at most 500"),
])
def test_item_validation(db, items, msg):
    sid, _h = _plant(db)
    with pytest.raises(ClassifyError, match=msg):
        classify_access_paths(db, sid, items)
    assert db.query(AccessPathTag).count() == 0


# ================================================================== bulk ==
def test_bulk_classify_every_row_and_counts(db):
    sid, h = _plant(db)
    _sess(db, h[HISTORIAN], h[FIELD], 41000, 502)
    db.commit()
    out = _get(db, sid)
    keys = [p["tag_key"] for p in out["paths"]] + [f["tag_key"] for f in out["unmatched_observed"]]
    res = _classify(db, sid, [{"tag_key": k, "classification": "permissive"} for k in keys])
    assert [i["tag_key"] for i in res["items"]] == keys
    assert db.query(AccessPathTag).count() == len(keys)
    kinds = {t.kind for t in db.query(AccessPathTag)}
    assert kinds == {"path", "composed", "unexplained"}
    comp = db.query(AccessPathTag).filter(AccessPathTag.kind == "composed").one()
    assert comp.policy_id == "1"                             # first leg's policy
    out = _get(db, sid)
    assert out["counts"]["by_classification"]["permissive"] == len(out["paths"])
    assert out["unmatched_observed"][0]["classification"] == "permissive"
    assert out["unmatched_observed"][0]["report_include"] is True     # flagged flow


def test_intrazone_rows_taggable_and_not_orphaned_when_hidden(db):
    sid = _site(db, "Intra")
    cfg = PLANT1_CFG.replace('''    edit 7
        set name "seg-deny-it-ot"''', '''    edit 70
        set name "l2-hairpin"
        set srcintf "port3"
        set dstintf "port3"
        set srcaddr "all"
        set dstaddr "all"
        set action accept
        set schedule "always"
        set service "MODBUS"
    next
    edit 7
        set name "seg-deny-it-ot"''')
    _ingest(db, cfg, "PLANT1-FGT", sid, PLANT1_LEVELS)
    same = [p for p in _get(db, sid, boundary_only=False)["paths"] if p["direction"] == "same"]
    assert same
    _classify(db, sid, [{"tag_key": same[0]["tag_key"], "classification": "reviewed_ok"}])
    assert _get(db, sid, boundary_only=True)["orphaned_tags"] == []


# ================================================================ orphans ==
def test_orphaned_tag_after_policy_removed(db):
    sid, _h = _plant(db)
    key = _row(_get(db, sid)["paths"], "6")["tag_key"]
    _classify(db, sid, [{"tag_key": key, "classification": "it_ot_bypass",
                         "report_include": True, "note": "remove it"}])
    start = PLANT1_CFG.index("    edit 6\n")
    end = PLANT1_CFG.index("    edit 8\n")
    _ingest(db, PLANT1_CFG[:start] + PLANT1_CFG[end:], "PLANT1-FGT", sid, PLANT1_LEVELS)
    out = _get(db, sid)
    assert key not in {p["tag_key"] for p in out["paths"]}
    assert out["counts"]["orphaned"] == 1 and out["orphaned_incomplete"] is False
    orphan = out["orphaned_tags"][0]
    assert orphan["tag_key"] == key and orphan["kind"] == "path"
    assert orphan["classification"] == "it_ot_bypass" and orphan["policy_id"] == "6"
    assert orphan["report_include"] is True and orphan["note"] == "remove it"
    # an orphaned key is not part of the current enumeration: cannot be classified
    with pytest.raises(ClassifyError):
        classify_access_paths(db, sid, [{"tag_key": key, "classification": "permissive"}])


# ================================================================== sites ==
def test_site_isolation(db):
    sid_a, _ = _plant(db, "Plant A", "PLANT1-FGT")
    sid_b, _ = _plant(db, "Plant B", "PLANT1-FGT")
    key_a = _row(_get(db, sid_a)["paths"], "6")["tag_key"]
    # identical configs give identical keys, but tags stay per site
    assert _row(_get(db, sid_b)["paths"], "6")["tag_key"] == key_a
    _classify(db, sid_a, [{"tag_key": key_a, "classification": "permissive"}])
    assert _row(_get(db, sid_b)["paths"], "6")["classification"] == "unclassified"
    assert _get(db, sid_b)["orphaned_tags"] == []
    # a key that exists only in another site is unknown here
    sid_c = _site(db, "Plant C")
    _ingest(db, PLANT1_CFG, "OTHER-FGT", sid_c, PLANT1_LEVELS)
    key_c = _row(_get(db, sid_c)["paths"], "6")["tag_key"]
    with pytest.raises(ClassifyError, match="unknown tag_key"):
        classify_access_paths(db, sid_a, [{"tag_key": key_c, "classification": "permissive"}])
    db.rollback()
    assert db.query(AccessPathTag).filter(AccessPathTag.site_id == sid_a).count() == 1


# =============================================================== endpoint ==
@pytest.fixture
def api(tmp_path, monkeypatch):
    import app.main as main_mod
    from fastapi.testclient import TestClient
    from sqlalchemy.orm import sessionmaker
    from app.db import Base as DBase, get_db, get_write_db, make_engine

    engine = make_engine(f"sqlite:///{tmp_path / 'tags.db'}")
    DBase.metadata.create_all(engine)
    Session = sessionmaker(bind=engine, autoflush=False)
    monkeypatch.setattr(main_mod, "init_db", lambda: None)
    calls = []
    monkeypatch.setattr("app.parsers.access_path_findings.sync_findings_for_tags",
                        lambda db, site_id, keys: calls.append((site_id, list(keys)))
                        or {"implemented": False})

    def _get_db():
        s = Session()
        try:
            yield s
        finally:
            s.close()

    ov = main_mod.app.dependency_overrides
    ov[get_db] = ov[get_write_db] = _get_db
    try:
        c = TestClient(main_mod.app)
        c.Session = Session
        c.sync_calls = calls
        yield c
    finally:
        ov.pop(get_db, None)
        ov.pop(get_write_db, None)
        engine.dispose()


def test_endpoint_classify_filters_and_sync(api):
    s = api.Session()
    sid_a, _ = _plant(s, "Plant A", "PLANT1-FGT")
    sid_b, _ = _plant(s, "Plant B", "OTHER-FGT")
    s.close()
    rows = api.get("/access-paths", params={"site_id": sid_a}).json()["paths"]
    k6 = _row(rows, "6")["tag_key"]
    k1 = _row(rows, "1")["tag_key"]

    r = api.post("/access-paths/classify", json={"site_id": sid_a, "items": [
        {"tag_key": k6, "classification": "it_ot_bypass", "note": "direct IT->PLC"},
        {"tag_key": k1, "classification": "reviewed_ok"}]})
    assert r.status_code == 200, r.text
    body = r.json()
    assert body["site_id"] == sid_a and [i["tag_key"] for i in body["items"]] == [k6, k1]
    assert body["items"][0]["classification"] == "it_ot_bypass"
    assert set(body["items"][0]) >= {"src", "dst", "chain", "flags", "traffic", "tag_key",
                                     "classification", "note", "classified_by",
                                     "classified_at", "report_include",
                                     "report_include_default"}
    assert api.sync_calls == [(sid_a, [k6, k1])]          # after commit, once

    j = api.get("/access-paths", params={"site_id": sid_a,
                                         "classification": "it_ot_bypass"}).json()
    assert [p["tag_key"] for p in j["paths"]] == [k6]
    j = api.get("/access-paths", params={"site_id": sid_a, "report_include": "false"}).json()
    assert k1 in {p["tag_key"] for p in j["paths"]}
    assert all(p["report_include"] is False for p in j["paths"])
    assert api.get("/access-paths", params={"site_id": sid_a,
                                            "classification": "nope"}).status_code == 422

    # another site's key -> 422, nothing stored, no sync
    r = api.post("/access-paths/classify", json={"site": sid_b, "items": [
        {"tag_key": k6, "classification": "permissive"}]})
    assert r.status_code == 422 and "unknown tag_key" in r.json()["detail"]
    s = api.Session()
    assert s.query(AccessPathTag).filter(AccessPathTag.site_id == sid_b).count() == 0
    s.close()
    assert len(api.sync_calls) == 1
    # two sites exist: the site is required
    assert api.post("/access-paths/classify",
                    json={"items": [{"tag_key": k6}]}).status_code == 422


# ============================================================== migration ==
def _cfg(url):
    from alembic.config import Config
    cfg = Config(str(PROJECT_ROOT / "alembic.ini"))
    cfg.set_main_option("script_location", str(PROJECT_ROOT / "alembic"))
    cfg.attributes["sqlalchemy.url"] = url
    cfg.attributes["skip_logging_config"] = True
    return cfg


def test_migration_fresh_upgrade_creates_tag_table_without_drift(tmp_path):
    from alembic import command
    from alembic.autogenerate import compare_metadata
    from alembic.runtime.migration import MigrationContext
    from app.db import Base

    url = f"sqlite:///{tmp_path / 'mig.db'}"
    command.upgrade(_cfg(url), "head")
    eng = sa.create_engine(url)
    try:
        insp = sa.inspect(eng)
        assert insp.has_table("access_path_tag")
        idx = {i["name"]: i for i in insp.get_indexes("access_path_tag")}
        assert idx["ux_access_path_tag_site_key"]["unique"]
        assert idx["ux_access_path_tag_site_key"]["column_names"] == ["site_id", "tag_key"]
        assert "ix_access_path_tag_site_id" in idx
        assert {c["name"]: c["nullable"] for c in insp.get_columns("access_path_tag")}["site_id"] is False
        with eng.connect() as conn:
            diffs = compare_metadata(MigrationContext.configure(conn, opts={"compare_type": True}),
                                     Base.metadata)
        assert diffs == [], diffs
        # idempotent: re-running the revision on an upgraded database is a no-op
        command.downgrade(_cfg(url), "e6f7a8b9c0d1")
        assert not sa.inspect(eng).has_table("access_path_tag")
        command.upgrade(_cfg(url), "head")
        assert sa.inspect(eng).has_table("access_path_tag")
    finally:
        eng.dispose()


def test_migration_offline_render_postgresql():
    pytest.importorskip("psycopg2")
    env = dict(os.environ, IACS_DATABASE_URL="postgresql+psycopg2://u:p@localhost/iasc")
    proc = subprocess.run([sys.executable, "-m", "alembic", "-c", str(PROJECT_ROOT / "alembic.ini"),
                           "upgrade", "head", "--sql"],
                          cwd=PROJECT_ROOT, capture_output=True, text=True, env=env)
    assert proc.returncode == 0, proc.stderr
    sql = proc.stdout.split("Running upgrade e6f7a8b9c0d1 -> f7a8b9c0d1e2", 1)[1]
    assert "CREATE TABLE IF NOT EXISTS access_path_tag" in sql
    assert "FOREIGN KEY(site_id) REFERENCES sites (id)" in sql
    assert ("CREATE UNIQUE INDEX IF NOT EXISTS ux_access_path_tag_site_key "
            "ON access_path_tag (site_id, tag_key)") in sql
    assert "CONSTRAINT ck_access_path_tag_classification CHECK" in sql
    proc = subprocess.run([sys.executable, "-m", "alembic", "-c", str(PROJECT_ROOT / "alembic.ini"),
                           "downgrade", "f7a8b9c0d1e2:e6f7a8b9c0d1", "--sql"],
                          cwd=PROJECT_ROOT, capture_output=True, text=True, env=env)
    assert proc.returncode == 0, proc.stderr
    assert "DROP TABLE IF EXISTS access_path_tag" in proc.stdout
