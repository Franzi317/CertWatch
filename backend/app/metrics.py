"""Prometheus /metrics endpoint + CertWatch-specific gauges (Task 9).

SECURITY NOTE: /metrics is intentionally UNAUTHENTICATED (Prometheus scrapers
don't send app session cookies/bearer tokens). In production this endpoint
must be restricted at the network layer (firewall rule / reverse-proxy
allowlist limiting it to the Prometheus scraper) -- do not expose it publicly.

Custom collectors query the DB fresh on every scrape via a
`prometheus_client` Collector (collect() is called once per GET /metrics),
so values are always current -- no background refresh loop needed.
"""
from __future__ import annotations

import logging
from datetime import timedelta

from fastapi import FastAPI
from prometheus_client import REGISTRY
from prometheus_client.core import GaugeMetricFamily
from prometheus_fastapi_instrumentator import Instrumentator
from sqlalchemy import func, select

from .db import SessionLocal
from .models import Certificate, ScanJob, WorkQueue, utcnow

log = logging.getLogger("certwatch.metrics")

_QUEUE_STATUSES = ("queued", "leased", "done", "failed")
_EXPIRY_WINDOWS_DAYS = (7, 30, 90)
# ponytail: Phase 0 has no dedicated worker-heartbeat table. Approximate
# liveness with the most recent WorkQueue.updated_at among non-queued rows
# (leased/done/failed) -- i.e. the last time a worker touched a row. A real
# heartbeat row/table can replace this in a later phase.
_HEARTBEAT_SENTINEL_SECONDS = 1e9  # emitted when the queue has never had activity


class CertWatchCollector:
    """Custom prometheus_client collector for CertWatch domain gauges.

    Registered once with the global REGISTRY; `collect()` runs on every
    /metrics scrape and opens its own short-lived DB session so metrics never
    go stale between scrapes.
    """

    def collect(self):
        queue_depth = GaugeMetricFamily(
            "certwatch_queue_depth",
            "Number of WorkQueue rows by status",
            labels=["status"],
        )
        certs_expiring = GaugeMetricFamily(
            "certwatch_certs_expiring_days",
            "Number of certificates with not_after within the given day window",
            labels=["window"],
        )
        scan_jobs_total = GaugeMetricFamily(
            "certwatch_scan_jobs_total",
            "Number of ScanJob rows by status",
            labels=["status"],
        )
        heartbeat = GaugeMetricFamily(
            "certwatch_worker_last_heartbeat_seconds",
            "Age in seconds of the most recent worker activity (approximated "
            "via the newest non-queued WorkQueue.updated_at; see ponytail note "
            "in app/metrics.py)",
        )

        try:
            self._populate(queue_depth, certs_expiring, scan_jobs_total, heartbeat)
        except Exception:
            # Never let a scrape 500 because the DB hiccuped -- log and fall
            # back to zeroed/sentinel metrics instead of raising.
            log.exception("certwatch metrics collection failed; emitting zeros")
            queue_depth = GaugeMetricFamily(
                "certwatch_queue_depth", "Number of WorkQueue rows by status", labels=["status"]
            )
            certs_expiring = GaugeMetricFamily(
                "certwatch_certs_expiring_days",
                "Number of certificates with not_after within the given day window",
                labels=["window"],
            )
            scan_jobs_total = GaugeMetricFamily(
                "certwatch_scan_jobs_total", "Number of ScanJob rows by status", labels=["status"]
            )
            heartbeat = GaugeMetricFamily(
                "certwatch_worker_last_heartbeat_seconds",
                "Age in seconds of the most recent worker activity (approximated)",
            )
            for status in _QUEUE_STATUSES:
                queue_depth.add_metric([status], 0)
            for days in _EXPIRY_WINDOWS_DAYS:
                certs_expiring.add_metric([str(days)], 0)
            heartbeat.add_metric([], _HEARTBEAT_SENTINEL_SECONDS)

        yield queue_depth
        yield certs_expiring
        yield scan_jobs_total
        yield heartbeat

    def _populate(self, queue_depth, certs_expiring, scan_jobs_total, heartbeat) -> None:
        db = SessionLocal()
        try:
            for status in _QUEUE_STATUSES:
                count = db.scalar(
                    select(func.count(WorkQueue.id)).where(WorkQueue.status == status)
                ) or 0
                queue_depth.add_metric([status], count)

            now = utcnow()
            for days in _EXPIRY_WINDOWS_DAYS:
                count = db.scalar(
                    select(func.count(Certificate.id)).where(
                        Certificate.not_after >= now,
                        Certificate.not_after <= now + timedelta(days=days),
                    )
                ) or 0
                certs_expiring.add_metric([str(days)], count)

            job_statuses = db.scalars(select(ScanJob.status).distinct()).all()
            for status in job_statuses:
                count = db.scalar(
                    select(func.count(ScanJob.id)).where(ScanJob.status == status)
                ) or 0
                scan_jobs_total.add_metric([status], count)

            last_activity = db.scalar(
                select(func.max(WorkQueue.updated_at)).where(WorkQueue.status != "queued")
            )
            if last_activity is not None:
                if last_activity.tzinfo is None:
                    # SQLite drops tzinfo on round-trip even for DateTime(timezone=True).
                    from datetime import timezone as _tz
                    last_activity = last_activity.replace(tzinfo=_tz.utc)
                age = max((now - last_activity).total_seconds(), 0.0)
                heartbeat.add_metric([], age)
            else:
                heartbeat.add_metric([], _HEARTBEAT_SENTINEL_SECONDS)
        finally:
            db.close()


_METRICS_REGISTERED = False


def setup_metrics(app: FastAPI) -> None:
    """Instrument `app` with default HTTP metrics + CertWatch gauges and
    expose them, unauthenticated, at GET /metrics.

    Idempotent: safe to call more than once in the same process (e.g. if a
    test session imports/creates the app repeatedly) -- guarded so we never
    hit prometheus_client's "Duplicated timeseries in CollectorRegistry"
    error on repeat registration.
    """
    global _METRICS_REGISTERED

    Instrumentator().instrument(app).expose(app, endpoint="/metrics", include_in_schema=False)

    if not _METRICS_REGISTERED:
        try:
            REGISTRY.register(CertWatchCollector())
        except ValueError:
            # Already registered (e.g. module re-imported in the same
            # process) -- fine, the existing collector is still serving.
            pass
        _METRICS_REGISTERED = True
