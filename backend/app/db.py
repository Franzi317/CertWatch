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
    _ensure_columns()


# ponytail: additive dev-migration for new nullable/defaulted columns so an existing
# SQLite DB keeps its data. Swap in Alembic if schema changes get non-trivial.
_ADDED_COLUMNS = {
    "targets": {
        "schedule_type": "VARCHAR(16) DEFAULT 'interval'",
        "schedule_time": "VARCHAR(5) DEFAULT '00:00'",
        "schedule_day": "INTEGER DEFAULT 0",
    },
}


def _ensure_columns() -> None:
    from sqlalchemy import inspect, text

    insp = inspect(engine)
    with engine.begin() as conn:
        for table, cols in _ADDED_COLUMNS.items():
            existing = {c["name"] for c in insp.get_columns(table)}
            for name, ddl in cols.items():
                if name not in existing:
                    conn.execute(text(f"ALTER TABLE {table} ADD COLUMN {name} {ddl}"))
