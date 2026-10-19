"""multi-fw-models

Revision ID: 946998cf677b
Revises: 0001baseline0
Create Date: 2026-09-27 21:46:20.549341

"""
import os
import sys
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa

# alembic/ holds the shared helpers; make them importable even for commands
# (heads, history) that load revisions without running env.py.
_ALEMBIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ALEMBIC_DIR not in sys.path:
    sys.path.insert(0, _ALEMBIC_DIR)

from iasc_migration_utils import (
    has_column,
    has_index,
    has_table,
    is_offline,
    unique_constraints_on,
)


# revision identifiers, used by Alembic.
revision: str = '946998cf677b'
down_revision: Union[str, Sequence[str], None] = '0001baseline0'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    """Upgrade schema.

    Idempotent (T1-02): every step is skipped when its object already
    exists, so this is a no-op on a database built by 0001baseline0 and a
    catch-up on a database stamped before this revision.
    """
    if not has_table('firewalls'):
        op.create_table('firewalls',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=255), nullable=False),
        sa.Column('device_name', sa.String(length=255), nullable=True),
        sa.Column('vendor', sa.String(length=32), nullable=False),
        sa.Column('source_file', sa.String(length=512), nullable=True),
        sa.Column('config_uploaded_at', sa.DateTime(), nullable=True),
        sa.Column('purdue_level_ingress', sa.Integer(), nullable=True),
        sa.Column('purdue_level_egress', sa.Integer(), nullable=True),
        sa.Column('upstream_firewall_id', sa.Integer(), nullable=True),
        sa.Column('topology_confirmed', sa.Boolean(), nullable=False),
        sa.Column('is_multi_fw', sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(['upstream_firewall_id'], ['firewalls.id'], ),
        sa.PrimaryKeyConstraint('id')
        )
    if not has_table('firewall_interfaces'):
        op.create_table('firewall_interfaces',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('firewall_id', sa.Integer(), nullable=False),
        sa.Column('name', sa.String(length=64), nullable=False),
        sa.Column('ip_address', sa.String(length=45), nullable=True),
        sa.Column('prefix_len', sa.Integer(), nullable=True),
        sa.Column('ip_cidr', sa.String(length=50), nullable=True),
        sa.Column('network_cidr', sa.String(length=50), nullable=True),
        sa.Column('vlan_id', sa.String(length=16), nullable=True),
        sa.Column('iface_type', sa.String(length=32), nullable=True),
        sa.Column('role', sa.String(length=32), nullable=True),
        sa.Column('allowaccess', sa.JSON(), nullable=True),
        sa.Column('status', sa.String(length=16), nullable=True),
        sa.Column('alias', sa.String(length=128), nullable=True),
        sa.Column('side', sa.String(length=16), nullable=True),
        sa.Column('zone_label', sa.String(length=128), nullable=True),
        sa.Column('purdue_level', sa.Integer(), nullable=True),
        sa.Column('connects_to_interface_id', sa.Integer(), nullable=True),
        sa.Column('is_ha', sa.Boolean(), nullable=False),
        sa.Column('is_mgmt_only', sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(['connects_to_interface_id'], ['firewall_interfaces.id'], ),
        sa.ForeignKeyConstraint(['firewall_id'], ['firewalls.id'], ),
        sa.PrimaryKeyConstraint('id'),
        sa.UniqueConstraint('firewall_id', 'name', name='uq_fw_interface_fw_name')
        )
    if not has_table('pcap_captures'):
        op.create_table('pcap_captures',
        sa.Column('id', sa.Integer(), nullable=False),
        sa.Column('uploaded_at', sa.DateTime(), nullable=True),
        sa.Column('firewall_id', sa.Integer(), nullable=True),
        sa.Column('interface_id', sa.Integer(), nullable=True),
        sa.Column('side', sa.String(length=16), nullable=True),
        sa.Column('filename', sa.String(length=512), nullable=True),
        sa.Column('capture_interface_raw', sa.String(length=128), nullable=True),
        sa.Column('packet_count', sa.Integer(), nullable=True),
        sa.Column('captured_at', sa.DateTime(), nullable=True),
        sa.Column('suggestion_confidence', sa.String(length=8), nullable=True),
        sa.Column('suggested_interface_id', sa.Integer(), nullable=True),
        sa.Column('operator_confirmed', sa.Boolean(), nullable=False),
        sa.ForeignKeyConstraint(['firewall_id'], ['firewalls.id'], ),
        sa.ForeignKeyConstraint(['interface_id'], ['firewall_interfaces.id'], ),
        sa.ForeignKeyConstraint(['suggested_interface_id'], ['firewall_interfaces.id'], ),
        sa.PrimaryKeyConstraint('id')
        )

    # T1-05: 'is_current IS 1' is invalid against a PostgreSQL boolean.
    if has_table('attestations') and not has_index('attestations', 'ix_attestation_one_current'):
        op.create_index('ix_attestation_one_current', 'attestations', ['checklist_id', 'baseline_id'], unique=True,
                        postgresql_where=sa.text('is_current = true'), sqlite_where=sa.text('is_current = 1'))

    # findings.source_ref: this revision originally replaced the plain index
    # with a global UNIQUE.  That global UNIQUE was wrong (T1-10: closed
    # findings could never recur) and is superseded by c3d4e5f6a7b8 (partial
    # unique on OPEN findings only).  Adding it here also fails outright on
    # legacy databases that already hold duplicate source_refs, so the step
    # is intentionally a no-op; c3d4e5f6a7b8 does the real work.

    # firewall_rules: add firewall_id column + FK (batch mode for SQLite compat)
    if has_table('firewall_rules') and not has_column('firewall_rules', 'firewall_id'):
        with op.batch_alter_table('firewall_rules', schema=None) as batch_op:
            batch_op.add_column(sa.Column('firewall_id', sa.Integer(), nullable=True))
            batch_op.create_foreign_key('fk_firewall_rules_firewall_id', 'firewalls', ['firewall_id'], ['id'])

    if has_table('hosts') and not has_index('hosts', 'ix_host_ip_only'):
        op.create_index('ix_host_ip_only', 'hosts', ['ip'], unique=True, postgresql_where=sa.text('mac IS NULL'), sqlite_where=sa.text('mac IS NULL'))
    if has_table('hosts') and not has_index('hosts', 'ix_host_mac_only'):
        op.create_index('ix_host_mac_only', 'hosts', ['mac'], unique=True, postgresql_where=sa.text('ip IS NULL'), sqlite_where=sa.text('ip IS NULL'))

    # network_sessions: add pcap_capture_id column + FK (batch mode for SQLite compat)
    if has_table('network_sessions') and not has_column('network_sessions', 'pcap_capture_id'):
        with op.batch_alter_table('network_sessions', schema=None) as batch_op:
            batch_op.add_column(sa.Column('pcap_capture_id', sa.Integer(), nullable=True))
            batch_op.create_foreign_key('fk_network_sessions_pcap_capture_id', 'pcap_captures', ['pcap_capture_id'], ['id'])


def downgrade() -> None:
    """Intentionally a no-op.

    The baseline revision (0001baseline0) already contains every object this
    revision adds, so "the schema at 0001baseline0" includes them.  Dropping
    them here would leave the database inconsistent with its stamped
    revision (and on PostgreSQL fails outright: firewall_devices.firewall_id
    references firewalls).  ``alembic downgrade base`` drops all tables via
    the baseline's downgrade.
    """
