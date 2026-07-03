"""Durable Postgres-backed work queue (Task 7).

Provides enqueue/claim/complete/fail primitives on top of `models.WorkQueue`.
Wiring an actual worker loop and switching `enqueue_scan` over to this queue
is out of scope here (Task 8) — this module only adds the primitives.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from sqlalchemy import or_, select
from sqlalchemy.orm import Session

from .models import WorkQueue


def enqueue(db: Session, kind: str, payload: dict, priority: int = 0) -> WorkQueue:
    item = WorkQueue(kind=kind, payload=payload, priority=priority)
    db.add(item)
    db.commit()
    db.refresh(item)
    return item


def claim(db: Session, lease_seconds: int = 300) -> WorkQueue | None:
    """Atomically pick one claimable row and mark it leased.

    Claimable = status == "queued", OR status == "leased" with an expired
    lease (the previous worker died mid-job). Ordered by priority desc, id
    asc (oldest highest-priority item first).
    """
    now = datetime.now(timezone.utc)
    stmt = (
        select(WorkQueue)
        .where(
            or_(
                WorkQueue.status == "queued",
                (WorkQueue.status == "leased") & (WorkQueue.lease_expires_at < now),
            )
        )
        .order_by(WorkQueue.priority.desc(), WorkQueue.id.asc())
        .limit(1)
    )

    dialect = db.get_bind().dialect.name
    if dialect == "postgresql":
        stmt = stmt.with_for_update(skip_locked=True)
    # ponytail: SQLite has no row locking / concurrent workers in this
    # deployment (single embedded worker), so a plain ordered SELECT inside
    # the session's transaction is race-free in practice. Do not rely on this
    # fallback for multi-process concurrency — that's what the Postgres
    # SKIP LOCKED path is for.

    item = db.execute(stmt).scalars().first()
    if item is None:
        return None

    item.status = "leased"
    item.lease_expires_at = now + timedelta(seconds=lease_seconds)
    item.attempts += 1
    db.commit()
    db.refresh(item)
    return item


def complete(db: Session, item: WorkQueue) -> None:
    item.status = "done"
    db.commit()


def fail(db: Session, item: WorkQueue, error: str) -> None:
    item.last_error = error
    if item.attempts < item.max_attempts:
        item.status = "queued"
        item.lease_expires_at = None
    else:
        item.status = "failed"
    db.commit()
