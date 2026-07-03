"""Tests for the User model and ROLE_RANK mapping (Phase 0, Task 3)."""
from app.models import ROLE_RANK, User


def test_user_defaults(db):
    user = User(email="alice@example.com")
    db.add(user)
    db.commit()
    db.refresh(user)

    reloaded = db.get(User, user.id)
    assert reloaded is not None
    assert reloaded.email == "alice@example.com"
    assert reloaded.role == "viewer"
    assert reloaded.disabled is False
    assert reloaded.source == "entra"


def test_role_rank_order():
    assert ROLE_RANK["admin"] > ROLE_RANK["operator"] > ROLE_RANK["viewer"]
