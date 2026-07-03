"""Tests for the queue-driven worker process (Task 8).

`worker.process_one(db)` claims one item from the Task 7 queue and, for
kind=="scan", runs the existing `scan_engine.run_scan_job`. These tests
monkeypatch `scan_engine.run_scan_job` so they don't need a real network scan.
"""
from app import scan_engine, scheduler, worker
from app.models import Target, WorkQueue


def _target(db) -> Target:
    t = Target(name="Lab box", target_type="ip", value="10.0.0.5", ports=[443])
    db.add(t)
    db.commit()
    db.refresh(t)
    return t


def test_process_one_runs_scan_job_and_marks_done(db, monkeypatch):
    seen = []
    monkeypatch.setattr(scan_engine, "run_scan_job", lambda job_id: seen.append(job_id))

    target = _target(db)
    job = scheduler.enqueue_scan(db, target, trigger="manual")

    result = worker.process_one(db)

    assert result is True
    assert seen == [job.id]
    item = db.query(WorkQueue).one()
    assert item.status == "done"
    assert item.payload["scan_job_id"] == job.id


def test_process_one_on_empty_queue_returns_false(db):
    assert worker.process_one(db) is False


def test_process_one_unknown_kind_fails_the_item(db):
    from app import queue

    item = queue.enqueue(db, "mystery", {"foo": "bar"})
    item.max_attempts = 1
    db.commit()

    result = worker.process_one(db)

    assert result is True
    db.refresh(item)
    assert item.status == "failed"
    assert "unknown kind" in item.last_error


def test_process_one_raising_stub_requeues_then_fails_at_max_attempts(db, monkeypatch):
    def _boom(job_id):
        raise RuntimeError("scan blew up")

    monkeypatch.setattr(scan_engine, "run_scan_job", _boom)

    target = _target(db)
    job = scheduler.enqueue_scan(db, target, trigger="manual")
    item = db.query(WorkQueue).one()
    item.max_attempts = 2
    db.commit()

    # First attempt: fails, but under max_attempts -> requeued.
    result1 = worker.process_one(db)
    assert result1 is True
    db.refresh(item)
    assert item.status == "queued"
    assert "scan blew up" in item.last_error

    # Second attempt: exhausts max_attempts -> failed for good.
    result2 = worker.process_one(db)
    assert result2 is True
    db.refresh(item)
    assert item.status == "failed"

    # Nothing left to claim.
    assert worker.process_one(db) is False
