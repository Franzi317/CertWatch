"""Test fixtures: isolated temp SQLite DB, ORM session, and API client.

Env is set before importing app modules so the engine binds to the temp DB.
"""
import os
import tempfile

os.environ["CERTWATCH_ENABLE_SCHEDULER"] = "false"
_fd, _path = tempfile.mkstemp(suffix=".db")
os.close(_fd)
os.environ["CERTWATCH_DATABASE_URL"] = f"sqlite:///{_path}"

import pytest  # noqa: E402
from fastapi.testclient import TestClient  # noqa: E402

from app.db import SessionLocal, engine  # noqa: E402
from app.main import app  # noqa: E402
from app.models import Base  # noqa: E402


@pytest.fixture
def db():
    Base.metadata.drop_all(engine)
    Base.metadata.create_all(engine)
    session = SessionLocal()
    try:
        yield session
    finally:
        session.close()


@pytest.fixture
def client():
    Base.metadata.drop_all(engine)
    with TestClient(app) as c:  # lifespan creates tables + seeds settings
        yield c
