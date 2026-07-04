"""LifecycleOrder state machine (Phase 1, Task 7): the approval-gated core
that governs every certificate issue/renew/revoke operation.

Renewals are APPROVAL-GATED by project decision (not auto-approved just
because a RenewalPolicy exists) and revoke requires ADMIN approval -- a
two-person rule so a single operator can never both request and approve a
revocation. Both gates are enforced in `approve()`, not at the DB layer.

The state graph (see ALLOWED_TRANSITIONS) is fail-closed: any transition not
explicitly listed raises ValueError, including from the three terminal
states (complete, failed, rolled_back), which have no outbound edges.
"""
from __future__ import annotations

from uuid import uuid4

from sqlalchemy import select
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from . import queue
from .models import LifecycleOrder, ManagedCertificate, utcnow

ALLOWED_TRANSITIONS: dict[str, set[str]] = {
    "pending_approval": {"approved", "failed"},
    "approved": {"queued", "failed"},
    "queued": {"issuing", "failed"},
    "issuing": {"deploying", "failed"},
    "deploying": {"verifying", "complete", "failed"},
    "verifying": {"complete", "failed", "rolled_back"},
    "complete": set(),
    "failed": set(),
    "rolled_back": set(),
}

TERMINAL_STATES = {"complete", "failed", "rolled_back"}


def _find_open_order(db: Session, managed_cert: ManagedCertificate, action: str) -> LifecycleOrder | None:
    existing = db.scalars(
        select(LifecycleOrder).where(
            LifecycleOrder.managed_certificate_id == managed_cert.id,
            LifecycleOrder.action == action,
        )
    ).all()
    for order in existing:
        if order.status not in TERMINAL_STATES:
            return order
    return None


def create_order(db: Session, managed_cert: ManagedCertificate, action: str, actor: str) -> tuple[LifecycleOrder, bool]:
    """Idempotent per (managed_cert, action): if an OPEN order (status not in
    TERMINAL_STATES) already exists for this pair, return it instead of
    creating a duplicate. This is genuinely race-safe (not just
    check-then-act): the DB enforces a partial unique index on
    (managed_certificate_id, action) restricted to open (non-terminal)
    statuses (see migration 0010), so even if two concurrent callers both
    pass the initial SELECT, only one INSERT can win -- the loser catches
    IntegrityError, rolls back, and re-reads the winner's row.

    Returns (order, created) where `created` is True only when this call
    actually inserted a new row."""
    existing = _find_open_order(db, managed_cert, action)
    if existing is not None:
        return existing, False

    order = LifecycleOrder(
        managed_certificate_id=managed_cert.id,
        action=action,
        status="pending_approval",
        correlation_id=str(uuid4()),
        transitions=[{"from": "", "to": "pending_approval", "at": utcnow().isoformat(), "detail": f"created by {actor}"}],
    )
    db.add(order)
    try:
        db.commit()
    except IntegrityError:
        db.rollback()
        existing = _find_open_order(db, managed_cert, action)
        if existing is None:
            raise
        return existing, False
    db.refresh(order)
    return order, True


def transition(db: Session, order: LifecycleOrder, to_status: str, detail: str = "") -> None:
    allowed = ALLOWED_TRANSITIONS.get(order.status, set())
    if to_status not in allowed:
        raise ValueError(f"illegal transition {order.status}->{to_status}")

    entry = {"from": order.status, "to": to_status, "at": utcnow().isoformat(), "detail": detail}
    # Reassign (don't mutate in place) so SQLAlchemy's change-tracking on the
    # JSON column sees a new list object and persists it.
    order.transitions = order.transitions + [entry]
    order.status = to_status
    db.commit()


def approve(db: Session, order: LifecycleOrder, actor: str, is_admin: bool) -> None:
    if order.status != "pending_approval":
        raise ValueError(f"cannot approve order in status {order.status}")
    if order.action == "revoke" and not is_admin:
        raise PermissionError("revoke approval requires admin (two-person rule)")

    order.approved_by = actor
    order.approved_at = utcnow()
    transition(db, order, "approved", detail=f"approved by {actor}")
    queue.enqueue(db, order.action, {"order_id": order.id})
    transition(db, order, "queued")


def reject(db: Session, order: LifecycleOrder, actor: str) -> None:
    if order.status != "pending_approval":
        raise ValueError(f"cannot reject order in status {order.status}")
    transition(db, order, "failed", detail=f"rejected by {actor}")
