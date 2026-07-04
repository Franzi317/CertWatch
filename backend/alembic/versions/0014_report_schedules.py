"""report_schedules

Revision ID: 0014
Revises: 0013
Create Date: 2026-07-04 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '0014'
down_revision: Union[str, None] = '0013'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('report_schedules',
    sa.Column('id', sa.Integer(), nullable=False),
    sa.Column('name', sa.String(length=255), nullable=False),
    sa.Column('report_type', sa.String(length=32), nullable=False),
    sa.Column('filter_params', sa.JSON(), nullable=False),
    sa.Column('format', sa.String(length=8), nullable=False),
    sa.Column('recipients', sa.JSON(), nullable=False),
    sa.Column('channel_id', sa.Integer(), nullable=False),
    sa.Column('cadence', sa.String(length=16), nullable=False),
    sa.Column('schedule_time', sa.String(length=5), nullable=False),
    sa.Column('schedule_day', sa.Integer(), nullable=False),
    sa.Column('enabled', sa.Boolean(), nullable=False),
    sa.Column('last_run_at', sa.DateTime(timezone=True), nullable=True),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.ForeignKeyConstraint(['channel_id'], ['notification_channels.id']),
    sa.PrimaryKeyConstraint('id')
    )
    op.create_index('ix_report_schedules_enabled', 'report_schedules', ['enabled'])


def downgrade() -> None:
    op.drop_index('ix_report_schedules_enabled', table_name='report_schedules')
    op.drop_table('report_schedules')
