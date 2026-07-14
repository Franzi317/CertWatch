"""chain ca fingerprints

Revision ID: 0017
Revises: 0016
Create Date: 2026-07-14 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = '0017'
down_revision: Union[str, None] = '0016'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('certificates', sa.Column('chain_ca_fingerprints', sa.JSON(), nullable=True))


def downgrade() -> None:
    op.drop_column('certificates', 'chain_ca_fingerprints')
