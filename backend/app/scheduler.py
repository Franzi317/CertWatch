"""APScheduler-driven scheduled scans (in-process, no external broker).

A single periodic job ticks every minute and enqueues a scan for any enabled
target whose scan_frequency has elapsed since its last scan. Keeping the scheduler
in-process keeps the deployment to one service for the MVP.
ponytail: in-process scheduler; move to a broker if you run multiple API replicas.
"""
from __future__ import annotations

import logging
import threading
from datetime import timedelta

from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy import select

from .db import SessionLocal
from .models import ScanJob, Target, utcnow
from .scan_engine import run_scan_job

log = logging.getLogger("certwatch.scheduler")
_scheduler: BackgroundScheduler | None = None


def start_job_thread(job_id: int) -> None:
    """Run a scan job in a daemon thread so the request returns immediately."""
    threading.Thread(target=run_scan_job, args=(job_id,), daemon=True).start()


def enqueue_scan(db, target: Target, trigger: str = "manual") -> ScanJob:
    job = ScanJob(target_id=target.id, target_name=target.name, status="pending", trigger=trigger)
    db.add(job)
    db.commit()
    start_job_thread(job.id)
    return job


def _tick() -> None:
    db = SessionLocal()
    try:
        now = utcnow()
        targets = db.scalars(select(Target).where(Target.enabled.is_(True))).all()
        for t in targets:
            due = t.last_scanned_at is None or (
                now - _aware(t.last_scanned_at) >= timedelta(minutes=t.scan_frequency_minutes)
            )
            if not due:
                continue
            # skip if a job for this target is already active
            active = db.scalar(select(ScanJob).where(
                ScanJob.target_id == t.id, ScanJob.status.in_(["pending", "running"])
            ))
            if active:
                continue
            enqueue_scan(db, t, trigger="scheduled")
            log.info("scheduled scan enqueued for target %s", t.name)
    except Exception:
        log.exception("scheduler tick failed")
    finally:
        db.close()


def _aware(dt):
    from datetime import timezone
    return dt.replace(tzinfo=timezone.utc) if dt.tzinfo is None else dt


def start_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        return
    _scheduler = BackgroundScheduler(daemon=True)
    _scheduler.add_job(_tick, "interval", minutes=1, id="scan_tick", max_instances=1)
    _scheduler.start()
    log.info("scheduler started")


def shutdown_scheduler() -> None:
    global _scheduler
    if _scheduler:
        _scheduler.shutdown(wait=False)
        _scheduler = None
