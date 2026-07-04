"""Tests for the LifecycleOrder state machine + approval gates (Phase 1,
Task 7). Renewals are approval-gated by project decision; revoke requires
admin approval (two-person rule)."""
from __future__ import annotations

import pytest
from conftest import login_as

from app import lifecycle, queue
from app.models import Certificate, Issuer, ManagedCertificate, RenewalPolicy, WorkQueue, utcnow

POLICY = {
    "name": "default-90d",
    "renew_before_days": 30,
    "key_algorithm": "rsa",
    "key_size": 2048,
    "max_retries": 3,
}


def _managed_cert(db, cn="host.example.com"):
    issuer = Issuer(name="corp-ca", issuer_type="adcs", config={})
    policy = RenewalPolicy(name="default-90d", renew_before_days=30, key_algorithm="rsa",
                           key_size=2048, require_approval=True, verify_after_deploy=True, max_retries=3)
    db.add(issuer)
    db.add(policy)
    db.flush()
    cert = Certificate(fingerprint_sha256=f"FP:{cn}", common_name=cn, sans=[cn], not_after=utcnow())
    db.add(cert)
    db.flush()
    m = ManagedCertificate(
        common_name=cn, sans=[cn], issuer_id=issuer.id, renewal_policy_id=policy.id,
        current_certificate_id=cert.id,
    )
    db.add(m)
    db.flush()
    return m


def test_create_order_starts_pending_approval(db):
    m = _managed_cert(db)
    order, _ = lifecycle.create_order(db, m, "renew", "alice@test.local")

    assert order.status == "pending_approval"
    assert order.action == "renew"
    assert order.managed_certificate_id == m.id
    assert order.correlation_id
    assert len(order.transitions) == 1
    assert order.transitions[0]["from"] == ""
    assert order.transitions[0]["to"] == "pending_approval"


def test_create_order_is_idempotent_for_same_open_action(db):
    m = _managed_cert(db)
    first, first_created = lifecycle.create_order(db, m, "renew", "alice@test.local")
    second, second_created = lifecycle.create_order(db, m, "renew", "alice@test.local")

    assert first.id == second.id
    assert first_created is True
    assert second_created is False
    from app.models import LifecycleOrder
    rows = db.query(LifecycleOrder).filter_by(managed_certificate_id=m.id, action="renew").all()
    assert len(rows) == 1


def test_create_order_after_terminal_creates_new_row(db):
    m = _managed_cert(db)
    first, _ = lifecycle.create_order(db, m, "renew", "alice@test.local")
    lifecycle.transition(db, first, "approved")
    lifecycle.transition(db, first, "queued")
    lifecycle.transition(db, first, "issuing")
    lifecycle.transition(db, first, "deploying")
    lifecycle.transition(db, first, "complete")

    second, second_created = lifecycle.create_order(db, m, "renew", "alice@test.local")
    assert second.id != first.id
    assert second_created is True


def test_create_order_race_safe_after_terminal_via_unique_index(db):
    """The partial unique index (migration 0010) permits a new open order
    for (managed_cert, action) only once the prior one is terminal -- this
    exercises that boundary via reject-to-failed instead of the full
    success path used by test_create_order_after_terminal_creates_new_row."""
    m = _managed_cert(db)
    first, first_created = lifecycle.create_order(db, m, "renew", "alice@test.local")
    assert first_created is True

    same, same_created = lifecycle.create_order(db, m, "renew", "alice@test.local")
    assert same.id == first.id
    assert same_created is False

    lifecycle.transition(db, first, "failed", detail="forced terminal for test")

    second, second_created = lifecycle.create_order(db, m, "renew", "alice@test.local")
    assert second_created is True
    assert second.id != first.id


def test_approve_renew_by_operator_queues_and_enqueues_work(db):
    m = _managed_cert(db)
    order, _ = lifecycle.create_order(db, m, "renew", "alice@test.local")

    lifecycle.approve(db, order, "bob@test.local", is_admin=False)

    assert order.status == "queued"
    assert order.approved_by == "bob@test.local"
    assert order.approved_at is not None

    items = db.query(WorkQueue).all()
    assert len(items) == 1
    assert items[0].payload == {"order_id": order.id}


def test_approve_revoke_requires_admin(db):
    m = _managed_cert(db)
    order, _ = lifecycle.create_order(db, m, "revoke", "alice@test.local")

    with pytest.raises(PermissionError):
        lifecycle.approve(db, order, "bob@test.local", is_admin=False)

    assert order.status == "pending_approval"


def test_approve_revoke_by_admin_succeeds(db):
    m = _managed_cert(db)
    order, _ = lifecycle.create_order(db, m, "revoke", "alice@test.local")

    lifecycle.approve(db, order, "carol@test.local", is_admin=True)

    assert order.status == "queued"
    items = db.query(WorkQueue).all()
    assert len(items) == 1


def test_approve_only_from_pending_approval(db):
    m = _managed_cert(db)
    order, _ = lifecycle.create_order(db, m, "renew", "alice@test.local")
    lifecycle.approve(db, order, "bob@test.local", is_admin=False)

    with pytest.raises(ValueError):
        lifecycle.approve(db, order, "bob@test.local", is_admin=False)


def test_reject_from_pending_approval_marks_failed(db):
    m = _managed_cert(db)
    order, _ = lifecycle.create_order(db, m, "renew", "alice@test.local")

    lifecycle.reject(db, order, "bob@test.local")

    assert order.status == "failed"
    assert "rejected by bob@test.local" in order.transitions[-1]["detail"]


def test_illegal_transition_from_terminal_state_raises(db):
    m = _managed_cert(db)
    order, _ = lifecycle.create_order(db, m, "renew", "alice@test.local")
    lifecycle.transition(db, order, "approved")
    lifecycle.transition(db, order, "queued")
    lifecycle.transition(db, order, "issuing")
    lifecycle.transition(db, order, "deploying")
    lifecycle.transition(db, order, "complete")

    with pytest.raises(ValueError):
        lifecycle.transition(db, order, "issuing")


def test_transition_reassigns_transitions_list(db):
    m = _managed_cert(db)
    order, _ = lifecycle.create_order(db, m, "renew", "alice@test.local")
    order_id = order.id

    lifecycle.transition(db, order, "approved", detail="looks good")

    assert order.status == "approved"
    assert order.transitions[-1]["detail"] == "looks good"
    assert order.transitions[-1]["from"] == "pending_approval"
    assert order.transitions[-1]["to"] == "approved"

    # Force a re-read from the DB (not the in-memory identity map cache) to
    # prove the JSON column actually persisted the new transition entry,
    # rather than merely mutating the in-memory object.
    db.expire(order)
    from app.models import LifecycleOrder
    reloaded = db.get(LifecycleOrder, order_id)
    assert reloaded.status == "approved"
    assert reloaded.transitions[-1]["detail"] == "looks good"
    assert reloaded.transitions[-1]["from"] == "pending_approval"
    assert reloaded.transitions[-1]["to"] == "approved"
    assert len(reloaded.transitions) == 2


# --------------------------------------------------------------------------- #
# Route tests
# --------------------------------------------------------------------------- #

def test_operator_creates_order_via_route(client, monkeypatch, db):
    m = _managed_cert(db)
    db.commit()
    login_as(client, "operator", monkeypatch)

    r = client.post("/api/lifecycle/orders", json={"managed_certificate_id": m.id, "action": "renew"})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["status"] == "pending_approval"
    assert body["action"] == "renew"

    r = client.get("/api/lifecycle/orders")
    assert r.status_code == 200
    assert len(r.json()) == 1

    r = client.get(f"/api/lifecycle/orders/{body['id']}")
    assert r.status_code == 200
    assert r.json()["id"] == body["id"]


def test_viewer_cannot_create_order(client, monkeypatch, db):
    m = _managed_cert(db)
    db.commit()
    login_as(client, "viewer", monkeypatch)

    r = client.post("/api/lifecycle/orders", json={"managed_certificate_id": m.id, "action": "renew"})
    assert r.status_code == 403


def test_create_order_bad_action_400(client, monkeypatch, db):
    m = _managed_cert(db)
    db.commit()
    login_as(client, "operator", monkeypatch)

    r = client.post("/api/lifecycle/orders", json={"managed_certificate_id": m.id, "action": "delete"})
    assert r.status_code == 400


def test_create_order_missing_managed_cert_404(client, monkeypatch, db):
    login_as(client, "operator", monkeypatch)

    r = client.post("/api/lifecycle/orders", json={"managed_certificate_id": 999999, "action": "renew"})
    assert r.status_code == 404


def test_approve_revoke_order_as_operator_403_as_admin_ok(client, monkeypatch, db):
    m = _managed_cert(db)
    db.commit()

    login_as(client, "operator", monkeypatch)
    r = client.post("/api/lifecycle/orders", json={"managed_certificate_id": m.id, "action": "revoke"})
    order_id = r.json()["id"]

    r = client.post(f"/api/lifecycle/orders/{order_id}/approve")
    assert r.status_code == 403, r.text

    login_as(client, "admin", monkeypatch)
    r = client.post(f"/api/lifecycle/orders/{order_id}/approve")
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "queued"


def test_reject_order_route(client, monkeypatch, db):
    m = _managed_cert(db)
    db.commit()
    login_as(client, "operator", monkeypatch)
    r = client.post("/api/lifecycle/orders", json={"managed_certificate_id": m.id, "action": "renew"})
    order_id = r.json()["id"]

    r = client.post(f"/api/lifecycle/orders/{order_id}/reject")
    assert r.status_code == 200, r.text
    assert r.json()["status"] == "failed"
