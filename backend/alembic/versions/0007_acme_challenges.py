"""acme_challenges

Revision ID: 0007
Revises: 0006
Create Date: 2026-07-03 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '0007'
down_revision: Union[str, None] = '0006'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.create_table('acme_challenges',
    sa.Column('token', sa.String(length=255), nullable=False),
    sa.Column('key_authorization', sa.Text(), nullable=False),
    sa.Column('created_at', sa.DateTime(timezone=True), nullable=False),
    sa.PrimaryKeyConstraint('token')
    )


def downgrade() -> None:
    op.drop_table('acme_challenges')
