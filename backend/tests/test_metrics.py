"""Tests for the Prometheus /metrics endpoint (Task 9).

`/metrics` is unauthenticated by design (Prometheus scrapers don't carry app
session cookies), so the default `client` fixture -- authenticated as admin
per conftest.py -- works fine here regardless of auth state.
"""
from app.db import SessionLocal
from app.main import app
from app.metrics import setup_metrics
from app.models import WorkQueue


def test_metrics_endpoint_returns_200_with_custom_gauges(client):
    r = client.get("/metrics")
    assert r.status_code == 200

    body = r.text
    assert "certwatch_queue_depth" in body
    assert "certwatch_certs_expiring_days" in body
    assert "certwatch_scan_jobs_total" in body
    assert "certwatch_worker_last_heartbeat_seconds" in body


def test_metrics_queue_depth_reflects_enqueued_row(client):
    db = SessionLocal()
    try:
        db.add(WorkQueue(kind="scan", payload={}, status="queued"))
        db.commit()
    finally:
        db.close()

    body = client.get("/metrics").text
    assert 'certwatch_queue_depth{status="queued"} 1.0' in body


def test_metrics_endpoint_ok_when_db_empty(client):
    # No rows seeded at all -- collectors must return zero counts, not 500.
    r = client.get("/metrics")
    assert r.status_code == 200
    assert 'certwatch_queue_depth{status="queued"} 0.0' in r.text


def test_setup_metrics_is_idempotent(client):
    # Calling setup_metrics twice on the same app must not raise (e.g. no
    # duplicate instrumentator middleware, no "Duplicated timeseries" error).
    setup_metrics(app)

    r = client.get("/metrics")
    assert r.status_code == 200
