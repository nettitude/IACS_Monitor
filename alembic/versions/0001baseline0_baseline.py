"""baseline: full schema

Root of the migration chain (T1-02). Before this revision existed the root
migration 946998cf677b ALTERed tables (attestations, hosts, findings, ...)
that no migration created, so ``alembic upgrade head`` could not build a
database from empty.

This revision creates the COMPLETE schema as of the T1 remediation
(i.e. identical to ``Base.metadata`` at head).  Every later revision is
written to be idempotent - it inspects the live schema and skips any
object that already exists - so:

  * a fresh database gets everything here and the later revisions are no-ops;
  * a database stamped at any older revision (946998cf677b, a1b2c3d4e5f6,
    b2c3d4e5f6a7) upgrades cleanly because the later revisions only add
    what is missing.

JSON columns use JSONB on PostgreSQL and generic JSON on SQLite, matching
``app.models._json_column``.  Partial indexes carry both
``postgresql_where`` (boolean literal ``true``) and ``sqlite_where``
(integer ``1``).

Revision ID: 0001baseline0
Revises:
Create Date: 2026-09-30 00:00:00.000000
"""
from typing import Sequence, Union

from alembic import op
import sqlalchemy as sa
from sqlalchemy.dialects import postgresql

# revision identifiers, used by Alembic.
revision: str = '0001baseline0'
down_revision: Union[str, Sequence[str], None] = None
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _json():
    """JSONB on PostgreSQL, generic JSON elsewhere (mirrors models._json_column)."""
    return postgresql.JSONB(astext_type=sa.Text()).with_variant(sa.JSON(), 'sqlite')


def upgrade() -> None:
    """Create the complete schema (as of the T1 remediation) on an empty database."""
    op.create_table('baselines',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('description', sa.String(length=1024), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('is_active', sa.Boolean(), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
    op.create_table('firewall_zones',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('device_name', sa.String(length=255), nullable=True),
    sa.Column('interface_name', sa.String(length=64), nullable=False),
    sa.Column('zone_name', sa.String(length=128), nullable=True),
    sa.Column('ip_cidr', sa.String(length=45), nullable=True),
    sa.Column('vlan_id', sa.String(length=16), nullable=True),
    sa.Column('interface_type', sa.String(length=32), nullable=True),
    sa.Column('source_file', sa.String(length=512), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('device_name', 'interface_name', name='uq_fw_zone_device_iface')
    )
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
    op.create_table('fortiana_events',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('received_at', sa.DateTime(), nullable=True),
    sa.Column('source_type', sa.String(length=16), nullable=False),
    sa.Column('device_name', sa.String(length=255), nullable=True),
    sa.Column('log_type', sa.String(length=64), nullable=True),
    sa.Column('subtype', sa.String(length=64), nullable=True),
    sa.Column('src_ip', sa.String(length=45), nullable=True),
    sa.Column('dst_ip', sa.String(length=45), nullable=True),
    sa.Column('src_port', sa.Integer(), nullable=True),
    sa.Column('dst_port', sa.Integer(), nullable=True),
    sa.Column('protocol', sa.String(length=16), nullable=True),
    sa.Column('action', sa.String(length=32), nullable=True),
    sa.Column('policy_id', sa.String(length=64), nullable=True),
    sa.Column('policy_name', sa.String(length=255), nullable=True),
    sa.Column('service', sa.String(length=64), nullable=True),
    sa.Column('app', sa.String(length=128), nullable=True),
    sa.Column('attack_name', sa.String(length=255), nullable=True),
    sa.Column('severity', sa.String(length=16), nullable=True),
    sa.Column('user', sa.String(length=128), nullable=True),
    sa.Column('src_user', sa.String(length=128), nullable=True),
    sa.Column('event_time', sa.DateTime(), nullable=True),
    sa.Column('raw_message', sa.Text(), nullable=True),
    sa.Column('raw_fields', _json(), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_fortiana_events_dst_ip'), 'fortiana_events', ['dst_ip'], unique=False)
    op.create_index(op.f('ix_fortiana_events_event_time'), 'fortiana_events', ['event_time'], unique=False)
    op.create_index(op.f('ix_fortiana_events_policy_id'), 'fortiana_events', ['policy_id'], unique=False)
    op.create_index(op.f('ix_fortiana_events_received_at'), 'fortiana_events', ['received_at'], unique=False)
    op.create_index(op.f('ix_fortiana_events_src_ip'), 'fortiana_events', ['src_ip'], unique=False)
    op.create_table('hosts',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('mac', sa.String(length=17), nullable=True),
    sa.Column('ip', sa.String(length=45), nullable=True),
    sa.Column('vendor', sa.String(length=128), nullable=True),
    sa.Column('hostname', sa.String(length=255), nullable=True),
    sa.Column('first_seen', sa.DateTime(), nullable=True),
    sa.Column('last_seen', sa.DateTime(), nullable=True),
    sa.Column('sources', _json(), nullable=True),
    sa.Column('device_type', sa.String(length=64), nullable=True),
    sa.Column('purdue_level', sa.Integer(), nullable=True),
    sa.Column('classification_source', sa.String(length=32), nullable=True),
    sa.Column('role', sa.String(length=64), nullable=True),
    sa.Column('role_source', sa.String(length=16), nullable=True),
    sa.Column('vlan', sa.String(length=64), nullable=True),
    sa.Column('vlan_source', sa.String(length=32), nullable=True),
    sa.Column('model', sa.String(length=128), nullable=True),
    sa.Column('serial_number', sa.String(length=128), nullable=True),
    sa.Column('firmware_version', sa.String(length=128), nullable=True),
    sa.Column('site', sa.String(length=128), nullable=True),
    sa.Column('building', sa.String(length=128), nullable=True),
    sa.Column('panel', sa.String(length=128), nullable=True),
    sa.Column('criticality', sa.String(length=16), nullable=True),
    sa.Column('is_safety_function', sa.Boolean(), nullable=True),
    sa.Column('owner', sa.String(length=128), nullable=True),
    sa.Column('asset_tag', sa.String(length=64), nullable=True),
    sa.Column('notes', sa.Text(), nullable=True),
    sa.Column('approved', sa.Boolean(), nullable=True),
    sa.Column('approved_by', sa.String(length=128), nullable=True),
    sa.Column('approved_at', sa.DateTime(), nullable=True),
    sa.Column('last_reviewed_at', sa.DateTime(), nullable=True),
    sa.Column('last_reviewed_by', sa.String(length=128), nullable=True),
    sa.CheckConstraint('ip IS NOT NULL OR mac IS NOT NULL', name='ck_host_identity'),
    sa.CheckConstraint('purdue_level IS NULL OR (purdue_level >= 0 AND purdue_level <= 5)', name='ck_host_purdue_level_range'),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('mac', 'ip', name='uq_host_mac_ip')
    )
    op.create_index('ix_host_ip_only', 'hosts', ['ip'], unique=True, postgresql_where=sa.text('mac IS NULL'), sqlite_where=sa.text('mac IS NULL'))
    op.create_index('ix_host_mac_only', 'hosts', ['mac'], unique=True, postgresql_where=sa.text('ip IS NULL'), sqlite_where=sa.text('ip IS NULL'))
    op.create_index(op.f('ix_hosts_ip'), 'hosts', ['ip'], unique=False)
    op.create_index(op.f('ix_hosts_mac'), 'hosts', ['mac'], unique=False)
    op.create_table('mac_table_entries',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('device_name', sa.String(length=255), nullable=True),
    sa.Column('port_name', sa.String(length=64), nullable=False),
    sa.Column('mac', sa.String(length=17), nullable=False),
    sa.Column('vlan', sa.String(length=64), nullable=True),
    sa.Column('source_file', sa.String(length=512), nullable=True),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_mac_table_entries_mac'), 'mac_table_entries', ['mac'], unique=False)
    op.create_table('switch_interfaces',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('device_name', sa.String(length=255), nullable=True),
    sa.Column('port_name', sa.String(length=64), nullable=False),
    sa.Column('vlan', sa.String(length=64), nullable=True),
    sa.Column('vlan_name', sa.String(length=128), nullable=True),
    sa.Column('mode', sa.String(length=16), nullable=True),
    sa.Column('description', sa.String(length=255), nullable=True),
    sa.Column('neighbor_device', sa.String(length=255), nullable=True),
    sa.Column('neighbor_port', sa.String(length=64), nullable=True),
    sa.Column('neighbor_platform', sa.String(length=255), nullable=True),
    sa.Column('neighbor_ip', sa.String(length=45), nullable=True),
    sa.Column('neighbor_protocol', sa.String(length=8), nullable=True),
    sa.Column('source_file', sa.String(length=512), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('device_name', 'port_name', name='uq_switch_iface_device_port')
    )
    op.create_table('switch_vlans',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('device_name', sa.String(length=255), nullable=True),
    sa.Column('vlan_id', sa.Integer(), nullable=False),
    sa.Column('vlan_name', sa.String(length=128), nullable=True),
    sa.Column('status', sa.String(length=16), nullable=True),
    sa.Column('port_count', sa.Integer(), nullable=True),
    sa.Column('purdue_level', sa.Integer(), nullable=True),
    sa.Column('purdue_level_source', sa.String(length=32), nullable=True),
    sa.Column('source_file', sa.String(length=512), nullable=True),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('device_name', 'vlan_id', name='uq_switch_vlan_device_vid')
    )
    op.create_table('approved_comms',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('baseline_id', sa.Integer(), nullable=False),
    sa.Column('src', sa.String(length=64), nullable=False),
    sa.Column('dst', sa.String(length=64), nullable=False),
    sa.Column('dst_port', sa.Integer(), nullable=True),
    sa.Column('protocol', sa.String(length=16), nullable=False),
    sa.Column('service_name', sa.String(length=128), nullable=True),
    sa.Column('conduit', sa.String(length=128), nullable=True),
    sa.Column('owner', sa.String(length=128), nullable=True),
    sa.ForeignKeyConstraint(['baseline_id'], ['baselines.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_approved_comms_lookup', 'approved_comms', ['baseline_id', 'src', 'dst', 'dst_port'], unique=False)
    op.create_table('approved_hosts',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('baseline_id', sa.Integer(), nullable=False),
    sa.Column('ip', sa.String(length=45), nullable=True),
    sa.Column('mac', sa.String(length=17), nullable=True),
    sa.Column('hostname', sa.String(length=255), nullable=True),
    sa.Column('role', sa.String(length=64), nullable=False),
    sa.Column('zone', sa.String(length=128), nullable=True),
    sa.Column('owner', sa.String(length=128), nullable=True),
    sa.Column('notes', sa.String(length=512), nullable=True),
    sa.ForeignKeyConstraint(['baseline_id'], ['baselines.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('attestations',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('checklist_id', sa.String(length=16), nullable=False),
    sa.Column('attested_by', sa.String(length=255), nullable=False),
    sa.Column('attested_at', sa.DateTime(), nullable=False),
    sa.Column('notes', sa.String(length=2048), nullable=True),
    sa.Column('proof_filename', sa.String(length=255), nullable=True),
    sa.Column('proof_mime', sa.String(length=128), nullable=True),
    sa.Column('proof_data', sa.LargeBinary(), nullable=True),
    sa.Column('baseline_id', sa.Integer(), nullable=True),
    sa.Column('is_current', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['baseline_id'], ['baselines.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_attestation_checklist_current', 'attestations', ['checklist_id', 'is_current'], unique=False)
    op.create_index('ix_attestation_one_current', 'attestations', ['checklist_id', 'baseline_id'], unique=True, postgresql_where=sa.text('is_current = true'), sqlite_where=sa.text('is_current = 1'))
    op.create_index('ix_attestation_one_current_nobaseline', 'attestations', ['checklist_id'], unique=True, postgresql_where=sa.text('is_current = true AND baseline_id IS NULL'), sqlite_where=sa.text('is_current = 1 AND baseline_id IS NULL'))
    op.create_index(op.f('ix_attestations_checklist_id'), 'attestations', ['checklist_id'], unique=False)
    op.create_table('firewall_devices',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('vendor', sa.String(length=32), nullable=True),
    sa.Column('device_hostname', sa.String(length=255), nullable=True),
    sa.Column('mgmt_ip', sa.String(length=45), nullable=True),
    sa.Column('firmware_version', sa.String(length=128), nullable=True),
    sa.Column('source_file', sa.String(length=512), nullable=True),
    sa.Column('purdue_zone_from', sa.Integer(), nullable=True),
    sa.Column('purdue_zone_to', sa.Integer(), nullable=True),
    sa.Column('firewall_id', sa.Integer(), nullable=True),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.ForeignKeyConstraint(['firewall_id'], ['firewalls.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('name')
    )
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
    sa.Column('allowaccess', _json(), nullable=True),
    sa.Column('status', sa.String(length=16), nullable=True),
    sa.Column('alias', sa.String(length=128), nullable=True),
    sa.Column('side', sa.String(length=16), nullable=True),
    sa.Column('zone_label', sa.String(length=128), nullable=True),
    sa.Column('purdue_level', sa.Integer(), nullable=True),
    sa.Column('suggested_purdue_level', sa.Integer(), nullable=True),
    sa.Column('purdue_suggestion_source', sa.String(length=32), nullable=True),
    sa.Column('connects_to_interface_id', sa.Integer(), nullable=True),
    sa.Column('parent_interface_id', sa.Integer(), nullable=True),
    sa.Column('is_ha', sa.Boolean(), nullable=False),
    sa.Column('is_mgmt_only', sa.Boolean(), nullable=False),
    sa.ForeignKeyConstraint(['connects_to_interface_id'], ['firewall_interfaces.id'], ),
    sa.ForeignKeyConstraint(['firewall_id'], ['firewalls.id'], ),
    sa.ForeignKeyConstraint(['parent_interface_id'], ['firewall_interfaces.id'], ),
    sa.PrimaryKeyConstraint('id'),
    sa.UniqueConstraint('firewall_id', 'name', name='uq_fw_interface_fw_name')
    )
    op.create_table('firewall_rules',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('device_name', sa.String(length=255), nullable=True),
    sa.Column('device_type', sa.String(length=32), nullable=False),
    sa.Column('source_file', sa.String(length=512), nullable=True),
    sa.Column('firewall_device_id', sa.Integer(), nullable=True),
    sa.Column('firewall_id', sa.Integer(), nullable=True),
    sa.Column('policy_id', sa.String(length=32), nullable=True),
    sa.Column('policy_name', sa.String(length=255), nullable=True),
    sa.Column('rule_order', sa.Integer(), nullable=True),
    sa.Column('src_zone', sa.String(length=128), nullable=True),
    sa.Column('dst_zone', sa.String(length=128), nullable=True),
    sa.Column('src', sa.String(length=128), nullable=True),
    sa.Column('dst', sa.String(length=128), nullable=True),
    sa.Column('protocol', sa.String(length=16), nullable=True),
    sa.Column('dst_port', sa.String(length=255), nullable=True),
    sa.Column('action', sa.String(length=16), nullable=False),
    sa.Column('owner', sa.String(length=255), nullable=True),
    sa.Column('conduit', sa.String(length=128), nullable=True),
    sa.Column('last_matched', sa.DateTime(), nullable=True),
    sa.Column('raw_line', sa.Text(), nullable=True),
    sa.ForeignKeyConstraint(['firewall_device_id'], ['firewall_devices.id'], ),
    sa.ForeignKeyConstraint(['firewall_id'], ['firewalls.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_firewall_rule_device_id', 'firewall_rules', ['firewall_device_id'], unique=False)
    op.create_index('ix_firewall_rule_order', 'firewall_rules', ['firewall_device_id', 'rule_order'], unique=False)
    op.create_index(op.f('ix_firewall_rules_policy_id'), 'firewall_rules', ['policy_id'], unique=False)
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
    op.create_table('network_sessions',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('src_host_id', sa.Integer(), nullable=False),
    sa.Column('dst_host_id', sa.Integer(), nullable=False),
    sa.Column('src_port', sa.Integer(), nullable=True),
    sa.Column('dst_port', sa.Integer(), nullable=True),
    sa.Column('transport', sa.String(length=8), nullable=False),
    sa.Column('protocol', sa.String(length=32), nullable=False),
    sa.Column('first_seen', sa.DateTime(), nullable=True),
    sa.Column('last_seen', sa.DateTime(), nullable=True),
    sa.Column('packet_count', sa.Integer(), nullable=True),
    sa.Column('byte_count', sa.Integer(), nullable=True),
    sa.Column('source_file', sa.String(length=512), nullable=True),
    sa.Column('pcap_capture_id', sa.Integer(), nullable=True),
    sa.ForeignKeyConstraint(['dst_host_id'], ['hosts.id'], ),
    sa.ForeignKeyConstraint(['pcap_capture_id'], ['pcap_captures.id'], ),
    sa.ForeignKeyConstraint(['src_host_id'], ['hosts.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_networksession_pcap_capture_id', 'network_sessions', ['pcap_capture_id'], unique=False)
    op.create_index('ix_session_5tuple', 'network_sessions', ['src_host_id', 'dst_host_id', 'src_port', 'dst_port', 'transport'], unique=False)
    op.create_table('findings',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(), nullable=True),
    sa.Column('updated_at', sa.DateTime(), nullable=True),
    sa.Column('category', sa.String(length=64), nullable=False),
    sa.Column('check_name', sa.String(length=64), nullable=True),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('isa62443_sr', sa.String(length=128), nullable=True),
    sa.Column('checklist_id', sa.String(length=64), nullable=True),
    sa.Column('title', sa.String(length=512), nullable=False),
    sa.Column('detail', _json(), nullable=True),
    sa.Column('device_name', sa.String(length=255), nullable=True),
    sa.Column('session_id', sa.Integer(), nullable=True),
    sa.Column('rule_id', sa.Integer(), nullable=True),
    sa.Column('forti_event_id', sa.Integer(), nullable=True),
    sa.Column('source_ref', sa.String(length=255), nullable=True),
    sa.Column('acknowledged_by', sa.String(length=128), nullable=True),
    sa.Column('acknowledged_at', sa.DateTime(), nullable=True),
    sa.Column('closed_at', sa.DateTime(), nullable=True),
    sa.Column('notes', sa.String(length=2048), nullable=True),
    sa.ForeignKeyConstraint(['forti_event_id'], ['fortiana_events.id'], ),
    sa.ForeignKeyConstraint(['rule_id'], ['firewall_rules.id'], ),
    sa.ForeignKeyConstraint(['session_id'], ['network_sessions.id'], ),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index(op.f('ix_findings_category'), 'findings', ['category'], unique=False)
    op.create_index(op.f('ix_findings_check_name'), 'findings', ['check_name'], unique=False)
    op.create_index(op.f('ix_findings_created_at'), 'findings', ['created_at'], unique=False)
    op.create_index(op.f('ix_findings_device_name'), 'findings', ['device_name'], unique=False)
    op.create_index(op.f('ix_findings_source_ref'), 'findings', ['source_ref'], unique=False)
    op.create_index(op.f('ix_findings_status'), 'findings', ['status'], unique=False)
    op.create_index('ux_findings_source_ref_open', 'findings', ['source_ref'], unique=True, sqlite_where=sa.text("status = 'open'"), postgresql_where=sa.text("status = 'open'"))
    op.create_table('protocol_details',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('session_id', sa.Integer(), nullable=False),
    sa.Column('protocol', sa.String(length=32), nullable=False),
    sa.Column('timestamp', sa.DateTime(), nullable=True),
    sa.Column('direction', sa.String(length=16), nullable=True),
    sa.Column('summary', sa.String(length=255), nullable=True),
    sa.Column('fields', _json(), nullable=True),
    sa.ForeignKeyConstraint(['session_id'], ['network_sessions.id'], ),
    sa.PrimaryKeyConstraint('id')
    )



def downgrade() -> None:
    """Drop every table (reverse dependency order). Indexes go with their tables."""
    bind = op.get_bind()
    existing = set(sa.inspect(bind).get_table_names())
    for name in (
        'protocol_details',
        'findings',
        'network_sessions',
        'pcap_captures',
        'firewall_rules',
        'firewall_interfaces',
        'firewall_devices',
        'attestations',
        'approved_hosts',
        'approved_comms',
        'switch_vlans',
        'switch_interfaces',
        'mac_table_entries',
        'hosts',
        'fortiana_events',
        'firewalls',
        'firewall_zones',
        'baselines',
    ):
        if name in existing:
            op.drop_table(name)
