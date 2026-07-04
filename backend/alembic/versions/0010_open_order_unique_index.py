"""open_order_unique_index

Revision ID: 0010
Revises: 0009
Create Date: 2026-07-03 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '0010'
down_revision: Union[str, None] = '0009'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    # Partial unique index: at most one OPEN (non-terminal) lifecycle order
    # per (managed_certificate_id, action). This is what actually makes
    # create_order's idempotency race-safe -- the SELECT-then-INSERT fast
    # path is just an optimization; this index is the real guarantee.
    op.create_index(
        "uq_open_lifecycle_order",
        "lifecycle_orders",
        ["managed_certificate_id", "action"],
        unique=True,
        sqlite_where=sa.text("status NOT IN ('complete','failed','rolled_back')"),
        postgresql_where=sa.text("status NOT IN ('complete','failed','rolled_back')"),
    )


def downgrade() -> None:
    op.drop_index("uq_open_lifecycle_order", table_name="lifecycle_orders")
