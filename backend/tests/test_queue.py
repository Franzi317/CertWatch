"""Tests for the Postgres-backed work queue (Task 7).

Runs against SQLite via the `db` fixture (see conftest.py); the claim()
function falls back to a plain ordered SELECT on SQLite (see queue.py) since
there's only ever one embedded worker in that environment.
"""
from datetime import datetime, timedelta, timezone

from app import queue
from app.models import WorkQueue


def _aware(dt: datetime) -> datetime:
    # SQLite drops tzinfo on round-trip even for DateTime(timezone=True)
    # columns; treat naive values as UTC (same convention as app/status.py).
    return dt if dt.tzinfo is not None else dt.replace(tzinfo=timezone.utc)


def test_enqueue_then_claim_marks_leased(db):
    queue.enqueue(db, "scan", {"target_id": 1})

    item = queue.claim(db)

    assert item is not None
    assert item.status == "leased"
    assert item.attempts == 1
    assert item.lease_expires_at is not None
    assert _aware(item.lease_expires_at) > datetime.now(timezone.utc)


def test_claim_on_empty_queue_returns_none(db):
    assert queue.claim(db) is None


def test_second_claim_on_otherwise_empty_queue_returns_none(db):
    queue.enqueue(db, "scan", {"target_id": 1})

    first = queue.claim(db)
    assert first is not None

    second = queue.claim(db)
    assert second is None


def test_fail_under_max_attempts_requeues(db):
    item = queue.enqueue(db, "scan", {"target_id": 1})
    item.max_attempts = 3
    db.commit()

    claimed = queue.claim(db)
    assert claimed.attempts == 1

    queue.fail(db, claimed, "boom")

    db.refresh(claimed)
    assert claimed.status == "queued"
    assert claimed.last_error == "boom"
    assert claimed.lease_expires_at is None

    # Should be claimable again.
    reclaimed = queue.claim(db)
    assert reclaimed is not None
    assert reclaimed.id == claimed.id
    assert reclaimed.attempts == 2


def test_fail_at_max_attempts_marks_failed(db):
    item = queue.enqueue(db, "scan", {"target_id": 1})
    item.max_attempts = 1
    db.commit()

    claimed = queue.claim(db)
    assert claimed.attempts == 1

    queue.fail(db, claimed, "boom")

    db.refresh(claimed)
    assert claimed.status == "failed"
    assert claimed.last_error == "boom"

    # Not claimable anymore.
    assert queue.claim(db) is None


def test_fail_exhausts_default_max_attempts_then_failed(db):
    item = queue.enqueue(db, "scan", {"target_id": 1})

    for expected_attempt in (1, 2, 3):
        claimed = queue.claim(db)
        assert claimed is not None
        assert claimed.id == item.id
        assert claimed.attempts == expected_attempt

        queue.fail(db, claimed, "boom")
        db.refresh(claimed)

        if expected_attempt < 3:
            assert claimed.status == "queued"
            assert claimed.lease_expires_at is None
        else:
            assert claimed.status == "failed"
            assert claimed.attempts == 3

    # Exhausted: no 4th execution.
    assert queue.claim(db) is None


def test_complete_marks_done_and_not_claimable(db):
    queue.enqueue(db, "scan", {"target_id": 1})
    claimed = queue.claim(db)

    queue.complete(db, claimed)

    db.refresh(claimed)
    assert claimed.status == "done"
    assert queue.claim(db) is None


def test_priority_ordering_claims_higher_priority_first(db):
    low = queue.enqueue(db, "scan", {"target_id": 1}, priority=0)
    high = queue.enqueue(db, "scan", {"target_id": 2}, priority=10)

    claimed = queue.claim(db)

    assert claimed.id == high.id
    assert claimed.id != low.id


def test_expired_lease_is_reclaimed(db):
    item = queue.enqueue(db, "scan", {"target_id": 1})
    claimed = queue.claim(db)
    assert claimed.status == "leased"

    # Simulate an expired lease (e.g. worker crashed before completing).
    claimed.lease_expires_at = datetime.now(timezone.utc) - timedelta(seconds=1)
    db.commit()

    reclaimed = queue.claim(db)

    assert reclaimed is not None
    assert reclaimed.id == item.id
    assert reclaimed.status == "leased"
    assert reclaimed.attempts == 2
    assert _aware(reclaimed.lease_expires_at) > datetime.now(timezone.utc)
