"""findings

Revision ID: 0013
Revises: 0012
Create Date: 2026-07-04 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '0013'
down_revision: Union[str, None] = '0012'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('findings',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('rule_id', sa.String(length=48), nullable=False),
    sa.Column('severity', sa.String(length=16), nullable=False),
    sa.Column('certificate_id', sa.Integer(), nullable=True),
    sa.Column('endpoint_id', sa.Integer(), nullable=True),
    sa.Column('title', sa.String(length=255), nullable=False),
    sa.Column('detail', sa.Text(), nullable=False),
    sa.Column('dedupe_key', sa.String(length=255), nullable=False),
    sa.Column('disposition', sa.String(length=16), nullable=False),
    sa.Column('status', sa.String(length=16), nullable=False),
    sa.Column('first_seen', sa.DateTime(timezone=True), nullable=False),
    sa.Column('last_seen', sa.DateTime(timezone=True), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['certificate_id'], ['certificates.id']),
    sa.ForeignKeyConstraint(['endpoint_id'], ['endpoints.id']),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_findings_dedupe_key', 'findings', ['dedupe_key'])


def downgrade() -> None:
    op.drop_index('ix_findings_dedupe_key', table_name='findings')
    op.drop_table('findings')
