"""Database engine and session management."""
from __future__ import annotations

from collections.abc import Iterator

from sqlalchemy import create_engine
from sqlalchemy.orm import Session, sessionmaker

from .config import settings

connect_args = {"check_same_thread": False} if settings.database_url.startswith("sqlite") else {}
engine = create_engine(settings.database_url, connect_args=connect_args, pool_pre_ping=True)
SessionLocal = sessionmaker(bind=engine, autoflush=False, expire_on_commit=False)


def get_db() -> Iterator[Session]:
    """FastAPI dependency yielding a request-scoped session."""
    db = SessionLocal()
    try:
        yield db
    finally:
        db.close()


def init_db() -> None:
    """Create tables. Adequate for SQLite/MVP; use migrations for prod schema changes."""
    from . import models  # noqa: F401  (register mappers)

    models.Base.metadata.create_all(bind=engine)


def run_migrations() -> None:
    """Run Alembic migrations up to head. Intended for production startup, where
    schema changes go through versioned migrations instead of create_all().

    Handles two starting states:
    - Fresh DB (no tables at all): alembic runs 0001..head normally.
    - Pre-Phase-0 DB (created by the old unconditional create_all(), so the app
      tables already exist physically but there's no alembic_version table):
      stamp it at 0001 (the baseline migration) so alembic knows the schema is
      already at that revision, then upgrade the rest of the way to head.
    """
    import pathlib

    from alembic import command
    from alembic.config import Config
    from sqlalchemy import inspect

    backend_dir = pathlib.Path(__file__).resolve().parents[1]
    cfg = Config(str(backend_dir / "alembic.ini"))
    cfg.set_main_option("script_location", str(backend_dir / "alembic"))
    cfg.set_main_option("sqlalchemy.url", settings.database_url)

    insp = inspect(engine)
    tables = set(insp.get_table_names())
    if "targets" in tables and "alembic_version" not in tables:
        # pre-Phase-0 DB: baseline schema already physically present -> stamp it, then upgrade
        command.stamp(cfg, "0001")
    command.upgrade(cfg, "head")
