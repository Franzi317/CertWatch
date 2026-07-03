"""Envelope encryption for notification-channel secrets (SMTP password, webhook URL).

Uses Fernet (symmetric, authenticated) keyed by `CERTWATCH_MASTER_KEY`, a
urlsafe-base64 32-byte key. Generate one with:

    python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"

Encrypted values are stored as `"enc:v1:" + <fernet token>`. `decrypt()` passes
plaintext values through unchanged (no prefix) so pre-encryption rows and
never-configured deployments keep working.

Phase 0 does not derive the key from a passphrase - the env var IS the key.
"""
from __future__ import annotations

from cryptography.fernet import Fernet, InvalidToken

PREFIX = "enc:v1:"

_fernet: Fernet | None = None
_loaded = False


class SecretsNotConfigured(Exception):
    """Raised when an encrypt/decrypt operation needs a key but none is set."""


def _load_fernet() -> Fernet | None:
    # Import here (not at module scope) and construct a fresh Settings() so
    # monkeypatch.setenv("CERTWATCH_MASTER_KEY", ...) is picked up after
    # _reset_cache() even though `app.config.settings` is a module-level
    # singleton built at import time.
    from .config import Settings

    key = Settings().master_key
    if not key:
        return None
    return Fernet(key.encode())


def _get_fernet() -> Fernet:
    global _fernet, _loaded
    if not _loaded:
        _fernet = _load_fernet()
        _loaded = True
    if _fernet is None:
        raise SecretsNotConfigured("CERTWATCH_MASTER_KEY is not configured")
    return _fernet


def _reset_cache() -> None:
    """Force the next encrypt/decrypt call to re-read the key from env. Test-only."""
    global _fernet, _loaded
    _fernet = None
    _loaded = False


def encrypt(plaintext: str) -> str:
    f = _get_fernet()
    return PREFIX + f.encrypt(plaintext.encode()).decode()


def decrypt(token: str) -> str:
    if not token or not token.startswith(PREFIX):
        return token
    f = _get_fernet()
    raw = token[len(PREFIX):].encode()
    try:
        return f.decrypt(raw).decode()
    except InvalidToken as e:
        raise SecretsNotConfigured("cannot decrypt: wrong or missing CERTWATCH_MASTER_KEY") from e


def is_encrypted(value: str) -> bool:
    return isinstance(value, str) and value.startswith(PREFIX)
