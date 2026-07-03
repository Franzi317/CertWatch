"""lifecycle_orders

Revision ID: 0009
Revises: 0008
Create Date: 2026-07-03 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '0009'
down_revision: Union[str, None] = '0008'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('lifecycle_orders',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('managed_certificate_id', sa.Integer(), nullable=False),
    sa.Column('action', sa.String(length=8), nullable=False),
    sa.Column('status', sa.String(length=20), nullable=False),
    sa.Column('attempts', sa.Integer(), nullable=False),
    sa.Column('approved_by', sa.String(length=255), nullable=False),
    sa.Column('approved_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('error', sa.Text(), nullable=False),
    sa.Column('correlation_id', sa.String(length=36), nullable=False),
    sa.Column('transitions', sa.JSON(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['managed_certificate_id'], ['managed_certificates.id']),
    sa.PrimaryKeyConstraint('id')
    )


def downgrade() -> None:
    op.drop_table('lifecycle_orders')
