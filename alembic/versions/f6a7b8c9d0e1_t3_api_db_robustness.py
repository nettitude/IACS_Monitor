"""t3-api-db-robustness: session 5-tuple UNIQUE, missing indexes, rule FK SET NULL

Tier-3 API/DB remediation:

1. approved_comms.dst_port_end (INTEGER NULL) - port ranges in the approved
   comms matrix ("1024-65535" -> dst_port=1024, dst_port_end=65535).
2. fortiana_events.dedup_hash (VARCHAR(40) NULL) + UNIQUE index
   ux_fortiana_events_dedup_hash - re-uploading the same syslog/CSV no
   longer duplicates events (T3-06).  Existing rows have NULL (never
   collide).
3. Indexes (T3-09): ix_protocol_details_session_id,
   ix_network_sessions_dst_host_id, ix_hosts_last_seen,
   ix_network_sessions_last_seen.
4. network_sessions 5-tuple UNIQUE (T3-10): existing duplicate sessions
   (same src_host_id, dst_host_id, src_port, dst_port, transport; rows with
   a NULL port never collide in a unique index and are left alone) are
   merged first:
     * the lowest id survives;
     * packet_count / byte_count are summed, first_seen = MIN,
       last_seen = MAX, an 'unknown' protocol / NULL pcap_capture_id is
       filled from a merged row;
     * protocol_details.session_id and findings.session_id are re-pointed
       to the survivor, then the other rows are deleted.
   Then ux_session_5tuple is created and the old non-unique
   ix_session_5tuple dropped.
5. findings.rule_id FK -> firewall_rules.id gets ON DELETE SET NULL (T3-19):
   a FortiGate config re-ingest deletes/recreates the firewall's rules,
   which failed on PostgreSQL (and on SQLite with foreign_keys=ON) for any
   rule a finding referenced.  SQLite: table rebuild via batch mode.

Idempotent (see alembic/iasc_migration_utils.py).  On an online upgrade
d4e5f6a7b8c9 (reconcile) may already have added 1-3 and, when there were
no duplicates, ux_session_5tuple from the live models; those steps are then
no-ops.  Offline (--sql) renders always emit the full DDL, because the
baseline revision predates every object added here (IF [NOT] EXISTS is used
where the dialect allows so the script is safe on either starting state).

Revision ID: f6a7b8c9d0e1
Revises: e5f6a7b8c9d0
Create Date: 2026-09-30 00:00:00.000000
"""
import logging
import os
import sys
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

_ALEMBIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ALEMBIC_DIR not in sys.path:
    sys.path.insert(0, _ALEMBIC_DIR)

from iasc_migration_utils import (  # noqa: E402
    dialect_name,
    has_column,
    has_index,
    has_table,
    is_offline,
)

revision: str = "f6a7b8c9d0e1"
down_revision: Union[str, Sequence[str], None] = "e5f6a7b8c9d0"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

log = logging.getLogger("alembic.runtime.migration")

_5TUPLE = ["src_host_id", "dst_host_id", "src_port", "dst_port", "transport"]
_RULE_FK_NAME = "fk_findings_rule_id_firewall_rules"
_NAMING = {"fk": "fk_%(table_name)s_%(column_0_name)s_%(referred_table_name)s"}

_PLAIN_INDEXES = [
    # (index name, table, columns)
    ("ix_protocol_details_session_id", "protocol_details", ["session_id"]),
    ("ix_network_sessions_dst_host_id", "network_sessions", ["dst_host_id"]),
    ("ix_hosts_last_seen", "hosts", ["last_seen"]),
    ("ix_network_sessions_last_seen", "network_sessions", ["last_seen"]),
]


def _need(table: str, column: str | None = None, index: str | None = None) -> bool:
    """True when the object must be created (always True offline)."""
    if is_offline():
        return True
    if not has_table(table):
        return False
    if column is not None:
        return not has_column(table, column)
    return not has_index(table, index)


# ---------------------------------------------------------------- sessions --

_SAME = " AND ".join(f"k.{c} = s.{c}" for c in _5TUPLE)
_GROUP = (
    "(d.id = network_sessions.id OR d.id IN "
    "(SELECT m.old_id FROM _iasc_session_merge m WHERE m.new_id = network_sessions.id))"
)

_MERGE_SQL = [
    "DROP TABLE IF EXISTS _iasc_session_merge",
    # old_id -> survivor (lowest id with the same 5-tuple).  '=' never matches
    # NULL, which is exactly the unique index's semantics.
    "CREATE TABLE _iasc_session_merge AS "
    "SELECT s.id AS old_id, "
    f"(SELECT MIN(k.id) FROM network_sessions k WHERE {_SAME}) AS new_id "
    "FROM network_sessions s "
    f"WHERE EXISTS (SELECT 1 FROM network_sessions k WHERE {_SAME} AND k.id < s.id)",
    "UPDATE network_sessions SET "
    f"packet_count = (SELECT SUM(COALESCE(d.packet_count, 0)) FROM network_sessions d WHERE {_GROUP}), "
    f"byte_count = (SELECT SUM(COALESCE(d.byte_count, 0)) FROM network_sessions d WHERE {_GROUP}), "
    f"first_seen = (SELECT MIN(d.first_seen) FROM network_sessions d WHERE {_GROUP}), "
    f"last_seen = (SELECT MAX(d.last_seen) FROM network_sessions d WHERE {_GROUP}), "
    "protocol = CASE WHEN protocol = 'unknown' THEN COALESCE("
    f"(SELECT MAX(d.protocol) FROM network_sessions d WHERE {_GROUP} AND d.protocol <> 'unknown'), "
    "protocol) ELSE protocol END, "
    "pcap_capture_id = COALESCE(pcap_capture_id, "
    f"(SELECT MAX(d.pcap_capture_id) FROM network_sessions d WHERE {_GROUP})) "
    "WHERE id IN (SELECT new_id FROM _iasc_session_merge)",
    "UPDATE protocol_details SET session_id = "
    "(SELECT m.new_id FROM _iasc_session_merge m WHERE m.old_id = protocol_details.session_id) "
    "WHERE session_id IN (SELECT old_id FROM _iasc_session_merge)",
    "UPDATE findings SET session_id = "
    "(SELECT m.new_id FROM _iasc_session_merge m WHERE m.old_id = findings.session_id) "
    "WHERE session_id IN (SELECT old_id FROM _iasc_session_merge)",
    "DELETE FROM network_sessions WHERE id IN (SELECT old_id FROM _iasc_session_merge)",
    "DROP TABLE _iasc_session_merge",
]


def _merge_duplicate_sessions() -> None:
    if not is_offline():
        bind = op.get_bind()
        n = bind.execute(sa.text(
            "SELECT COUNT(*) FROM (SELECT 1 FROM network_sessions "
            "WHERE src_port IS NOT NULL AND dst_port IS NOT NULL "
            "GROUP BY " + ", ".join(_5TUPLE) + " HAVING COUNT(*) > 1) g"
        )).scalar()
        if not n:
            return
        log.info("f6a7b8c9d0e1: merging %d duplicate network_sessions 5-tuple group(s)", n)
    for stmt in _MERGE_SQL:
        op.execute(stmt)


def _upgrade_sessions() -> None:
    if not is_offline() and not has_table("network_sessions"):
        return
    if _need("network_sessions", index="ux_session_5tuple"):
        _merge_duplicate_sessions()
        op.create_index("ux_session_5tuple", "network_sessions", _5TUPLE,
                        unique=True, if_not_exists=is_offline() or None)
    if is_offline():
        op.drop_index("ix_session_5tuple", table_name="network_sessions", if_exists=True)
    elif has_index("network_sessions", "ix_session_5tuple"):
        op.drop_index("ix_session_5tuple", table_name="network_sessions")


# ------------------------------------------------------------- rule FK --

def _rule_fk():
    """The reflected findings.rule_id FK dict, or None."""
    for fk in sa.inspect(op.get_bind()).get_foreign_keys("findings"):
        if fk.get("constrained_columns") == ["rule_id"] and fk.get("referred_table") == "firewall_rules":
            return fk
    return None


def _upgrade_rule_fk() -> None:
    if is_offline():
        if dialect_name() == "postgresql":
            # The baseline created the FK unnamed -> PostgreSQL's default name.
            op.execute("ALTER TABLE findings DROP CONSTRAINT IF EXISTS findings_rule_id_fkey")
            op.execute(f"ALTER TABLE findings DROP CONSTRAINT IF EXISTS {_RULE_FK_NAME}")
            op.create_foreign_key(_RULE_FK_NAME, "findings", "firewall_rules",
                                  ["rule_id"], ["id"], ondelete="SET NULL")
        else:
            # SQLite needs a reflected table rebuild, impossible offline.
            op.execute("-- f6a7b8c9d0e1: findings.rule_id ON DELETE SET NULL requires "
                       "an online upgrade on SQLite (table rebuild)")
        return
    if not has_table("findings") or not has_column("findings", "rule_id"):
        return
    fk = _rule_fk()
    if fk is not None and str((fk.get("options") or {}).get("ondelete") or "").upper() == "SET NULL":
        return
    if dialect_name() == "sqlite":
        with op.batch_alter_table("findings", recreate="always",
                                  naming_convention=_NAMING) as batch:
            if fk is not None:
                batch.drop_constraint(fk.get("name") or _RULE_FK_NAME, type_="foreignkey")
            batch.create_foreign_key(_RULE_FK_NAME, "firewall_rules",
                                     ["rule_id"], ["id"], ondelete="SET NULL")
    else:
        if fk is not None and fk.get("name"):
            op.drop_constraint(fk["name"], "findings", type_="foreignkey")
        op.create_foreign_key(_RULE_FK_NAME, "findings", "firewall_rules",
                              ["rule_id"], ["id"], ondelete="SET NULL")


# ------------------------------------------------------------------ main --

def upgrade() -> None:
    offline = is_offline()

    if _need("approved_comms", column="dst_port_end"):
        op.add_column("approved_comms", sa.Column("dst_port_end", sa.Integer(), nullable=True),
                      if_not_exists=offline or None)

    if _need("fortiana_events", column="dedup_hash"):
        op.add_column("fortiana_events", sa.Column("dedup_hash", sa.String(length=40), nullable=True),
                      if_not_exists=offline or None)
    if _need("fortiana_events", index="ux_fortiana_events_dedup_hash"):
        op.create_index("ux_fortiana_events_dedup_hash", "fortiana_events", ["dedup_hash"],
                        unique=True, if_not_exists=offline or None)

    for name, table, cols in _PLAIN_INDEXES:
        if _need(table, index=name):
            op.create_index(name, table, cols, unique=False, if_not_exists=offline or None)

    _upgrade_sessions()
    _upgrade_rule_fk()


def downgrade() -> None:
    """Restore the pre-revision schema, except:
      * merged duplicate sessions are not split again (the data is summed);
      * findings.rule_id keeps ON DELETE SET NULL (harmless for older code,
        and a SQLite table rebuild just to weaken an FK is not worth it).
    """
    offline = is_offline()
    if offline or has_index("network_sessions", "ux_session_5tuple"):
        op.drop_index("ux_session_5tuple", table_name="network_sessions",
                      if_exists=offline or None)
    if offline or (has_table("network_sessions")
                   and not has_index("network_sessions", "ix_session_5tuple")):
        op.create_index("ix_session_5tuple", "network_sessions", _5TUPLE, unique=False,
                        if_not_exists=offline or None)

    for name, table, _cols in _PLAIN_INDEXES:
        if offline or has_index(table, name):
            op.drop_index(name, table_name=table, if_exists=offline or None)

    if offline or has_index("fortiana_events", "ux_fortiana_events_dedup_hash"):
        op.drop_index("ux_fortiana_events_dedup_hash", table_name="fortiana_events",
                      if_exists=offline or None)
    for table, column in (("fortiana_events", "dedup_hash"), ("approved_comms", "dst_port_end")):
        if offline or has_column(table, column):
            with op.batch_alter_table(table) as batch:
                batch.drop_column(column)
