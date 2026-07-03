"""encrypt channel secrets

Data migration: for every row in notification_channels, encrypt the
`password` and `url` keys of the JSON `config` column with app.secrets.encrypt
(Fernet, "enc:v1:"-prefixed) unless they're already encrypted or empty.

If CERTWATCH_MASTER_KEY isn't configured this is a no-op (with a warning) so
an existing dev DB without a configured key still migrates cleanly - the
values stay plaintext until a key is set and the app re-saves the channel
(create_channel/update_channel encrypt on write going forward).

Revision ID: 0002
Revises: 0001
Create Date: 2026-07-03 00:00:00.000000

"""
import json
import logging
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

# revision identifiers, used by Alembic.
revision: str = '0002'
down_revision: Union[str, None] = '0001'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None

log = logging.getLogger("alembic.0002_encrypt_channel_secrets")

_SECRET_KEYS = ("password", "url")

_channels_table = sa.table(
    "notification_channels",
    sa.column("id", sa.Integer),
    sa.column("config", sa.JSON),
)


def upgrade() -> None:
    from app.secrets import SecretsNotConfigured, encrypt, is_encrypted

    bind = op.get_bind()
    rows = bind.execute(sa.select(_channels_table.c.id, _channels_table.c.config)).fetchall()

    for row_id, config in rows:
        if not config:
            continue
        # SQLite may hand back JSON as a str; normalize to dict.
        if isinstance(config, str):
            config = json.loads(config)
        changed = False
        for key in _SECRET_KEYS:
            value = config.get(key)
            if value and not is_encrypted(value):
                try:
                    config[key] = encrypt(value)
                    changed = True
                except SecretsNotConfigured:
                    log.warning(
                        "CERTWATCH_MASTER_KEY not configured; skipping encryption of "
                        "notification_channels.id=%s config[%r] (left as plaintext)",
                        row_id, key,
                    )
        if changed:
            bind.execute(
                _channels_table.update()
                .where(_channels_table.c.id == row_id)
                .values(config=config)
            )


def downgrade() -> None:
    # No-op: decrypting back to plaintext on downgrade isn't implemented.
    # ponytail: acceptable ceiling for Phase 0 - downgrade path just leaves
    # secrets encrypted; app.secrets.decrypt() is back-compat either way.
    pass
