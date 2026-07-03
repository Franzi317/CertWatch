import pytest
from app import secrets as s

def test_roundtrip(monkeypatch):
    from cryptography.fernet import Fernet
    monkeypatch.setenv("CERTWATCH_MASTER_KEY", Fernet.generate_key().decode())
    s._reset_cache()  # force re-read of env
    tok = s.encrypt("hunter2")
    assert tok.startswith("enc:v1:")
    assert s.is_encrypted(tok)
    assert s.decrypt(tok) == "hunter2"

def test_decrypt_passthrough_plaintext():
    assert s.decrypt("plain-not-encrypted") == "plain-not-encrypted"

def test_encrypt_unconfigured_raises(monkeypatch):
    monkeypatch.setenv("CERTWATCH_MASTER_KEY", "")
    s._reset_cache()
    with pytest.raises(s.SecretsNotConfigured):
        s.encrypt("x")
