"""deployment_targets

Revision ID: 0012
Revises: 0011
Create Date: 2026-07-03 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '0012'
down_revision: Union[str, None] = '0011'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('deployment_targets',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('kind', sa.String(length=8), nullable=False),
    sa.Column('config', sa.JSON(), nullable=False),
    sa.Column('post_deploy_command', sa.Text(), nullable=False),
    sa.Column('managed_certificate_id', sa.Integer(), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('last_deploy_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('last_deploy_ok', sa.Boolean(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['managed_certificate_id'], ['managed_certificates.id']),
    sa.PrimaryKeyConstraint('id')
    )


def downgrade() -> None:
    op.drop_table('deployment_targets')
