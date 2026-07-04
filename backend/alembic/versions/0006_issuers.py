"""issuers

Revision ID: 0006
Revises: 0005
Create Date: 2026-07-03 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '0006'
down_revision: Union[str, None] = '0005'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('issuers',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('issuer_type', sa.String(length=16), nullable=False),
    sa.Column('config', sa.JSON(), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('last_test_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_test_ok', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    with op.batch_alter_table('issuers', schema=None) as batch_op:
        batch_op.create_index(batch_op.f('ix_issuers_name'), ['name'], unique=True)


def downgrade() -> None:
    with op.batch_alter_table('issuers', schema=None) as batch_op:
        batch_op.drop_index(batch_op.f('ix_issuers_name'))

    op.drop_table('issuers')
