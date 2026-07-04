"""APScheduler-driven scheduled scans (in-process, no external broker).

A single periodic job ticks every minute and enqueues a scan for any enabled
target whose scan_frequency has elapsed since its last scan. Keeping the scheduler
in-process keeps the deployment to one service for the MVP.
ponytail: in-process scheduler; move to a broker if you run multiple API replicas.
"""
from __future__ import annotations

import logging
from datetime import datetime, timedelta, timezone

from apscheduler.schedulers.background import BackgroundScheduler
from sqlalchemy import select

from . import alerts, lifecycle, queue
from .config import settings
from .db import SessionLocal
from .models import (
    Certificate,
    LifecycleOrder,
    ManagedCertificate,
    ReportSchedule,
    RenewalPolicy,
    ScanJob,
    Target,
    WorkQueue,
    utcnow,
)

log = logging.getLogger("certwatch.scheduler")
_scheduler: BackgroundScheduler | None = None

# Task 13: how long a LifecycleOrder may sit in a non-terminal state (e.g.
# "issuing"/"deploying") before order_stuck_tick treats it as abandoned --
# most plausibly a worker crash mid-order, since every legitimate step
# either advances the order or fails it closed within seconds.
ORDER_STUCK_THRESHOLD = timedelta(hours=2)


def enqueue_scan(db, target: Target, trigger: str = "manual") -> ScanJob:
    """Create the ScanJob row and hand it to the Task 7/8 work queue instead
    of running it in-process. A worker (embedded thread or the dedicated
    `worker` service) claims and executes it (see `app.worker.process_one`)."""
    job = ScanJob(target_id=target.id, target_name=target.name, status="pending", trigger=trigger)
    db.add(job)
    db.commit()
    queue.enqueue(db, "scan", {"scan_job_id": job.id})
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


def renewal_tick() -> None:
    """Daily job (Task 8): find every ManagedCertificate whose current
    certificate is within its RenewalPolicy's renew_before_days window and
    open a "renew" LifecycleOrder for it. Approval-gated by project decision
    -- this NEVER auto-approves, it only creates the pending_approval order
    (`lifecycle.create_order` is idempotent, so re-running this tick is safe:
    an already-open renew order for the same managed cert is reused, not
    duplicated -- see migration 0010's partial unique index)."""
    db = SessionLocal()
    try:
        now = utcnow()
        managed_certs = db.scalars(
            select(ManagedCertificate).where(ManagedCertificate.state == "active")
        ).all()
        for managed in managed_certs:
            if managed.current_certificate_id is None:
                continue
            cert = db.get(Certificate, managed.current_certificate_id)
            if cert is None or cert.not_after is None:
                continue
            policy = db.get(RenewalPolicy, managed.renewal_policy_id)
            if policy is None:
                continue
            not_after = _aware(cert.not_after)
            if not_after - now <= timedelta(days=policy.renew_before_days):
                lifecycle.create_order(db, managed, "renew", actor="system")
                log.info("renewal order opened for managed certificate %s", managed.id)
    except Exception:
        log.exception("renewal tick failed")
    finally:
        db.close()


def order_stuck_tick() -> None:
    """Task 13: find every LifecycleOrder in a non-terminal state whose
    `updated_at` is older than ORDER_STUCK_THRESHOLD and raise an
    `order_stuck` AlertEvent for it (deduped per order via
    `alerts.raise_alert`, so re-running this tick every few minutes doesn't
    spam). This is the safety net for a worker crash mid-issuance/deploy: the
    order would otherwise sit in e.g. "issuing" forever with nothing else
    watching it."""
    db = SessionLocal()
    try:
        now = utcnow()
        open_orders = db.scalars(
            select(LifecycleOrder).where(LifecycleOrder.status.notin_(list(lifecycle.TERMINAL_STATES)))
        ).all()
        for order in open_orders:
            if now - _aware(order.updated_at) < ORDER_STUCK_THRESHOLD:
                continue
            managed = db.get(ManagedCertificate, order.managed_certificate_id)
            cn = managed.common_name if managed else str(order.managed_certificate_id)
            alerts.raise_alert(
                db,
                dedupe_key=f"order_stuck:{order.id}",
                rule_type="order_stuck",
                severity="warning",
                message=(
                    f"Lifecycle order {order.id} ({order.action}) for {cn} has been stuck in "
                    f"'{order.status}' since {order.updated_at.isoformat()} -- possible worker "
                    "crash or hang; investigate the queue and worker logs."
                ),
                certificate_id=managed.current_certificate_id if managed else None,
            )
    except Exception:
        log.exception("order_stuck tick failed")
    finally:
        db.close()


def report_due(schedule: ReportSchedule, now_utc: datetime) -> bool:
    """True if `schedule` should run now. Same calendar-window logic as
    `schedule_due`'s calendar branch (daily/weekly/monthly), but keyed off
    `last_run_at` instead of `last_scanned_at` -- ReportSchedule has no
    "interval" cadence, only calendar ones."""
    last = _aware(schedule.last_run_at) if schedule.last_run_at else None
    hh, mm = _parse_hhmm(getattr(schedule, "schedule_time", "08:00"))
    now_local = now_utc.astimezone(settings.tzinfo)
    occ = _last_occurrence(schedule.cadence, hh, mm, getattr(schedule, "schedule_day", 0) or 0, now_local)
    if occ is None:
        return False
    occ_utc = occ.astimezone(timezone.utc)
    return last is None or last < occ_utc


def report_tick() -> None:
    db = SessionLocal()
    try:
        now = utcnow()
        schedules = db.scalars(select(ReportSchedule).where(ReportSchedule.enabled.is_(True))).all()
        # skip schedules with an already in-flight "report" item -- report_due()
        # only flips False once the worker sets last_run_at, so without this a
        # backlogged/down worker would get the same schedule re-enqueued every
        # minute (mirrors _tick()'s active-ScanJob check above).
        # ponytail: full scan of open report items each tick is fine at this scale.
        pending = db.scalars(select(WorkQueue).where(
            WorkQueue.kind == "report", WorkQueue.status.in_(["queued", "leased"]),
        )).all()
        inflight_ids = {w.payload.get("schedule_id") for w in pending}
        for s in schedules:
            if not report_due(s, now):
                continue
            if s.id in inflight_ids:
                continue
            queue.enqueue(db, "report", {"schedule_id": s.id})
            log.info("scheduled report enqueued: %s", s.name)
    except Exception:
        log.exception("report tick failed")
    finally:
        db.close()


def start_scheduler() -> None:
    global _scheduler
    if _scheduler is not None:
        return
    _scheduler = BackgroundScheduler(daemon=True)
    _scheduler.add_job(_tick, "interval", minutes=1, id="scan_tick", max_instances=1)
    _scheduler.add_job(renewal_tick, "interval", hours=24, id="renewal_tick", max_instances=1)
    _scheduler.add_job(order_stuck_tick, "interval", minutes=5, id="order_stuck_tick", max_instances=1)
    _scheduler.add_job(report_tick, "interval", minutes=1, id="report_tick", max_instances=1)
    _scheduler.start()
    log.info("scheduler started")


def shutdown_scheduler() -> None:
    global _scheduler
    if _scheduler:
        _scheduler.shutdown(wait=False)
        _scheduler = None
