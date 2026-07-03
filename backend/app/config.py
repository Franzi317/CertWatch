"""Runtime configuration, sourced from environment variables.

Secrets (SMTP password, webhook URLs) are never hardcoded — they come from the
environment or are stored per-channel in the DB and never returned in API
responses. See `.env.example`.
"""
from __future__ import annotations

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
