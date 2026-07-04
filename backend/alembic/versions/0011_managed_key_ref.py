"""managed_key_ref

Revision ID: 0011
Revises: 0010
Create Date: 2026-07-03 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '0011'
down_revision: Union[str, None] = '0010'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Encrypted (via app.secrets) PEM of the private key generated for the
    # ManagedCertificate's current certificate. Needed at deployment time to
    # build the PFX/PEM bundle (Task 9) -- never stored in plaintext.
    op.add_column(
        'managed_certificates',
        sa.Column('current_key_ref', sa.Text(), nullable=False, server_default=''),
    )


def downgrade() -> None:
    op.drop_column('managed_certificates', 'current_key_ref')
