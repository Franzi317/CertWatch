"""APScheduler-driven scheduled scans (in-process, no external broker).

A single periodic job ticks every minute and enqueues a scan for any enabled
target whose scan_frequency has elapsed since its last scan. Keeping the scheduler
in-process keeps the deployment to one service for the MVP.
ponytail: in-process scheduler; move to a broker if you run multiple API replicas.
"""
from __future__ import annotations

import logging
import threading
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy import select

from .config import settings
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


def _parse_hhmm(s: str) -> tuple[int, int]:
    try:
        hh, mm = (s or "00:00").split(":")
        return max(0, min(23, int(hh))), max(0, min(59, int(mm)))
    except (ValueError, AttributeError):
        return 0, 0


def _last_occurrence(schedule_type: str, hh: int, mm: int, day: int, now_local: datetime):
    """Most recent local datetime this calendar schedule should have fired, <= now."""
    at = lambda d: d.replace(hour=hh, minute=mm, second=0, microsecond=0)
    if schedule_type == "daily":
        base = at(now_local)
        return base if base <= now_local else base - timedelta(days=1)
    if schedule_type == "weekly":
        for delta in range(0, 8):  # scan back up to a week for the matching weekday
            d = now_local - timedelta(days=delta)
            fire = at(d)
            if d.weekday() == day and fire <= now_local:
                return fire
        return None
    if schedule_type == "monthly":
        dom = min(max(day, 1), 28)  # cap at 28 so every month has the day
        fire = at(now_local.replace(day=dom))
        if fire <= now_local:
            return fire
        prev_month_last = now_local.replace(day=1) - timedelta(days=1)
        return at(prev_month_last.replace(day=dom))
    return None


def schedule_due(t: Target, now_utc: datetime) -> bool:
    """True if target t should scan now. Interval uses minutes; calendar types fire
    once per window (with catch-up if the app was down when the window opened)."""
    last = _aware(t.last_scanned_at) if t.last_scanned_at else None
    st = getattr(t, "schedule_type", "interval") or "interval"
    if st == "interval":
        return last is None or now_utc - last >= timedelta(minutes=t.scan_frequency_minutes)
    hh, mm = _parse_hhmm(getattr(t, "schedule_time", "00:00"))
    now_local = now_utc.astimezone(settings.tzinfo)
    occ = _last_occurrence(st, hh, mm, getattr(t, "schedule_day", 0) or 0, now_local)
    if occ is None:
        return False
    occ_utc = occ.astimezone(timezone.utc)
    return last is None or last < occ_utc


def _tick() -> None:
    db = SessionLocal()
    try:
        now = utcnow()
        targets = db.scalars(select(Target).where(Target.enabled.is_(True))).all()
        for t in targets:
            if not schedule_due(t, now):
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
