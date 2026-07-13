"""certificate source column

Revision ID: 0015
Revises: 0014
Create Date: 2026-07-12 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = '0015'
down_revision: Union[str, None] = '0014'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('certificates', sa.Column('source', sa.String(length=16),
                  nullable=False, server_default='network'))


def downgrade() -> None:
    op.drop_column('certificates', 'source')
