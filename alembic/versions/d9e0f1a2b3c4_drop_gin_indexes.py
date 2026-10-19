"""drop the JSONB GIN indexes (AU full review F4)

a1b2c3d4e5f6 created GIN indexes on findings.detail and
protocol_details.fields "for @> / ? lookups" that no query in the
application ever issues.  They were not declared on the models either, so
schema comparison reported them as drift, and a GIN index on
protocol_details costs every pcap ingest insert.  Dropped (PostgreSQL only;
SQLite never had them).

Fresh installs; idempotent.  No app.models import.

Revision ID: d9e0f1a2b3c4
Revises: c8d9e0f1a2b3
Create Date: 2026-10-06 18:30:00.000000
"""
from typing import Sequence, Union

from alembic import op

revision: str = "d9e0f1a2b3c4"
down_revision: Union[str, Sequence[str], None] = "c8d9e0f1a2b3"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def _is_postgresql() -> bool:
    return op.get_bind().dialect.name == "postgresql"


def upgrade() -> None:
    if _is_postgresql():
        op.execute("DROP INDEX IF EXISTS ix_protocol_details_fields_gin")
        op.execute("DROP INDEX IF EXISTS ix_findings_detail_gin")


def downgrade() -> None:
    if _is_postgresql():
        op.execute("CREATE INDEX IF NOT EXISTS ix_findings_detail_gin ON findings USING GIN (detail)")
        op.execute("CREATE INDEX IF NOT EXISTS ix_protocol_details_fields_gin "
                   "ON protocol_details USING GIN (fields)")
