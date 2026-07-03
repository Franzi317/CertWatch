"""Runtime configuration, sourced from environment variables.

Secrets (SMTP password, webhook URLs) are never hardcoded — they come from the
environment or are stored per-channel in the DB and never returned in API
responses. See `.env.example`.
"""
from __future__ import annotations

import secrets as _pysecrets

from pydantic import model_validator
from pydantic_settings import BaseSettings, SettingsConfigDict


class Settings(BaseSettings):
    model_config = SettingsConfigDict(env_prefix="CERTWATCH_", env_file=".env", extra="ignore")

    # SQLite for local dev; set to a postgresql+psycopg2://... URL for production.
    database_url: str = "sqlite:///./certwatch.db"

    # Optional bearer token. When unset, the API is open (local single-user mode).
    # Auth is intentionally minimal — see README "Authentication" / future work.
    api_key: str = ""

    # CORS origins for the React dev server. Comma-separated.
    cors_origins: str = "http://localhost:5173,http://localhost:3000"

    # Comma-separated substrings matched (case-insensitive) against a cert's issuer
    # DN to classify it as internally-issued. Self-signed certs are always internal.
    internal_ca_patterns: str = ""

    # Scan safety guardrails.
    max_cidr_hosts: int = 4096          # refuse to expand a target larger than this
    default_timeout: float = 5.0        # seconds per TLS connection
    default_concurrency: int = 50       # simultaneous connections per scan job
    default_ports: str = "443"          # default ports when a target lists none

    # Run the in-process scheduler (set false when running pure API/worker splits).
    enable_scheduler: bool = True

    # IANA timezone that calendar schedules (daily/weekly/monthly start times) are
    # interpreted in. Falls back to UTC if unset or invalid. DST-aware via zoneinfo.
    timezone: str = "UTC"

    # Path to built frontend (served as static in production). Empty = API only.
    static_dir: str = ""

    # Fernet key (urlsafe-base64, 32 bytes) used to envelope-encrypt notification
    # channel secrets (SMTP password, webhook URL) at rest. Generate with:
    #   python -c "from cryptography.fernet import Fernet; print(Fernet.generate_key().decode())"
    # Empty = secret writes are refused (see app.secrets.SecretsNotConfigured).
    master_key: str = ""

    # Break-glass local admin (Phase 0, used by Task 4's login flow). Empty
    # admin_email disables the break-glass path entirely. admin_password_hash
    # is a bcrypt hash string, never a plaintext password.
    admin_email: str = ""
    admin_password_hash: str = ""

    # Session cookie signing key (Task 4). If unset, a random per-process key
    # is generated below (ponytail: fine for dev/single-instance; set
    # CERTWATCH_SESSION_SECRET explicitly anywhere sessions must survive a
    # restart or be shared across multiple app processes).
    session_secret: str = ""
    # Set to false only for local HTTP dev without TLS; production must be true.
    cookie_secure: bool = True

    # Entra ID (Azure AD) OIDC app registration. Empty tenant/client disables
    # the real IdP path; tests exercise the callback via a monkeypatched
    # app.auth._fetch_token and never need these populated.
    entra_tenant_id: str = ""
    entra_client_id: str = ""
    entra_client_secret: str = ""
    entra_redirect_uri: str = ""

    # Comma-separated Entra group object IDs mapped to each role. The highest
    # role whose group set intersects the user's IdP groups wins; no match
    # falls back to "viewer". See app.auth.map_groups_to_role.
    entra_admin_group: str = ""
    entra_operator_group: str = ""
    entra_viewer_group: str = ""

    @model_validator(mode="after")
    def _fill_ephemeral_session_secret(self) -> "Settings":
        # ponytail: no CERTWATCH_SESSION_SECRET configured — generate a random
        # per-process secret so login still works in dev/tests. Every process
        # restart invalidates existing session cookies until this is set.
        if not self.session_secret:
            self.session_secret = _pysecrets.token_hex(32)
        return self

    @property
    def cors_origin_list(self) -> list[str]:
        return [o.strip() for o in self.cors_origins.split(",") if o.strip()]

    @property
    def internal_ca_pattern_list(self) -> list[str]:
        return [p.strip() for p in self.internal_ca_patterns.split(",") if p.strip()]

    @property
    def tzinfo(self):
        from zoneinfo import ZoneInfo, ZoneInfoNotFoundError
        try:
            return ZoneInfo(self.timezone)
        except (ZoneInfoNotFoundError, ValueError):
            return ZoneInfo("UTC")


settings = Settings()
