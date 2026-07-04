"""managed_certs

Revision ID: 0008
Revises: 0007
Create Date: 2026-07-03 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '0008'
down_revision: Union[str, None] = '0007'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('renewal_policies',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('renew_before_days', sa.Integer(), nullable=False),
    sa.Column('key_algorithm', sa.String(length=16), nullable=False),
    sa.Column('key_size', sa.Integer(), nullable=False),
    sa.Column('require_approval', sa.Boolean(), nullable=False),
    sa.Column('verify_after_deploy', sa.Boolean(), nullable=False),
    sa.Column('max_retries', sa.Integer(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_table('managed_certificates',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('common_name', sa.String(length=255), nullable=False),
    sa.Column('sans', sa.JSON(), nullable=False),
    sa.Column('issuer_id', sa.Integer(), nullable=False),
    sa.Column('renewal_policy_id', sa.Integer(), nullable=False),
    sa.Column('current_certificate_id', sa.Integer(), nullable=True),
    sa.Column('state', sa.String(length=16), nullable=False),
    sa.Column('owner', sa.String(length=255), nullable=False),
    sa.Column('environment', sa.String(length=64), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.Column('updated_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['issuer_id'], ['issuers.id']),
    sa.ForeignKeyConstraint(['renewal_policy_id'], ['renewal_policies.id']),
    sa.ForeignKeyConstraint(['current_certificate_id'], ['certificates.id']),
    sa.PrimaryKeyConstraint('id')
    )


def downgrade() -> None:
    op.drop_table('managed_certificates')
    op.drop_table('renewal_policies')
