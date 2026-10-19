"""access-path-tag: operator classifications of access-path rows

docs/access-path-review.md, "Data model" (phase 3).

  access_path_tag (id, site_id FK sites NOT NULL, tag_key VARCHAR(512) NOT NULL,
                   kind VARCHAR(16) NOT NULL, firewall_device_id INTEGER NULL,
                   vdom VARCHAR(64) NULL, policy_id VARCHAR(32) NULL,
                   classification VARCHAR(16) NOT NULL, report_include BOOLEAN NULL,
                   note TEXT NULL, classified_by VARCHAR(128) NULL,
                   classified_at DATETIME NULL, updated_at DATETIME NULL)
      ux_access_path_tag_site_key (site_id, tag_key) UNIQUE
      ix_access_path_tag_site_id (site_id)
      ck_access_path_tag_kind            kind IN (path, composed, unexplained)
      ck_access_path_tag_classification  classification IN (unclassified,
                                         permissive, it_ot_bypass, reviewed_ok,
                                         exception)

firewall_device_id is descriptive only (no FK): tags are matched by
tag_key, which uses the firewall NAME so a delete-and-re-add keeps them.

Fresh installs only.  Idempotent (alembic/iasc_migration_utils.py): the table
and each index are created only when missing.  Offline (--sql) renders emit
the full DDL with IF NOT EXISTS (the baseline predates this table).  A new
table needs no batch mode on SQLite.  No app.models import.

Revision ID: f7a8b9c0d1e2
Revises: e6f7a8b9c0d1
Create Date: 2026-10-05 09:00:00.000000
"""
import os
import sys
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

_ALEMBIC_DIR = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
if _ALEMBIC_DIR not in sys.path:
    sys.path.insert(0, _ALEMBIC_DIR)

from iasc_migration_utils import has_index, has_table, is_offline  # noqa: E402

revision: str = "f7a8b9c0d1e2"
down_revision: Union[str, Sequence[str], None] = "e6f7a8b9c0d1"
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

_T = "access_path_tag"
_UX = "ux_access_path_tag_site_key"
_IX = "ix_access_path_tag_site_id"
# Mirrored verbatim from app.models (migrations never import app).
_KINDS = ("path", "composed", "unexplained")
_CLASSES = ("unclassified", "permissive", "it_ot_bypass", "reviewed_ok", "exception")


def _in_list(column, values):
    return f"{column} IN ({', '.join(repr(v) for v in values)})"


def _create_table(if_not_exists: bool) -> None:
    op.create_table(
        _T,
        sa.Column("id", sa.Integer(), nullable=False),
        sa.Column("site_id", sa.Integer(), nullable=False),
        sa.Column("tag_key", sa.String(length=512), nullable=False),
        sa.Column("kind", sa.String(length=16), nullable=False),
        sa.Column("firewall_device_id", sa.Integer(), nullable=True),
        sa.Column("vdom", sa.String(length=64), nullable=True),
        sa.Column("policy_id", sa.String(length=32), nullable=True),
        sa.Column("classification", sa.String(length=16), nullable=False),
        sa.Column("report_include", sa.Boolean(), nullable=True),
        sa.Column("note", sa.Text(), nullable=True),
        sa.Column("classified_by", sa.String(length=128), nullable=True),
        sa.Column("classified_at", sa.DateTime(), nullable=True),
        sa.Column("updated_at", sa.DateTime(), nullable=True),
        sa.ForeignKeyConstraint(["site_id"], ["sites.id"]),
        sa.PrimaryKeyConstraint("id"),
        sa.CheckConstraint(_in_list("kind", _KINDS), name="ck_access_path_tag_kind"),
        sa.CheckConstraint(_in_list("classification", _CLASSES),
                           name="ck_access_path_tag_classification"),
        if_not_exists=if_not_exists,
    )


def upgrade() -> None:
    if is_offline():
        _create_table(if_not_exists=True)
        op.create_index(_UX, _T, ["site_id", "tag_key"], unique=True, if_not_exists=True)
        op.create_index(_IX, _T, ["site_id"], if_not_exists=True)
        return
    if not has_table(_T):
        _create_table(if_not_exists=False)
    if not has_index(_T, _UX):
        op.create_index(_UX, _T, ["site_id", "tag_key"], unique=True)
    if not has_index(_T, _IX):
        op.create_index(_IX, _T, ["site_id"])


def downgrade() -> None:
    if is_offline():
        op.execute(f"DROP INDEX IF EXISTS {_IX}")
        op.execute(f"DROP INDEX IF EXISTS {_UX}")
        op.execute(f"DROP TABLE IF EXISTS {_T}")
        return
    if has_table(_T):
        if has_index(_T, _IX):
            op.drop_index(_IX, table_name=_T)
        if has_index(_T, _UX):
            op.drop_index(_UX, table_name=_T)
        op.drop_table(_T)
