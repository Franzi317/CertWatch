"""Tests for scheduled CSV reports delivered by email (Phase 2, Task 5).

Covers `reports.render` (CSV projection of the cert inventory), the
`/api/reports` CRUD + RBAC, `/api/reports/{id}/run` draining through
`worker.process_one` (with `notify.send_email` monkeypatched so no real SMTP
call happens), and the `report_due` calendar-schedule helper used by
`scheduler.report_tick`.
"""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from conftest import login_as

from app import reports, worker
from app.models import Certificate, NotificationChannel, ReportSchedule, WorkQueue, utcnow
from app.scheduler import report_due


def _cert(db, **kw) -> Certificate:
    base = dict(
        fingerprint_sha256=kw.pop("fingerprint_sha256", "ff" * 32),
        common_name="example.com",
        issuer_cn="Test CA",
        not_before=utcnow() - timedelta(days=10),
        not_after=utcnow() + timedelta(days=20),
    )
    base.update(kw)
    c = Certificate(**base)
    db.add(c)
    db.commit()
    db.refresh(c)
    return c


def _channel(db, **kw) -> NotificationChannel:
    base = dict(
        name="mail", channel_type="smtp", enabled=True,
        config={"host": "smtp.example.com", "recipients": ["ops@example.com"]},
    )
    base.update(kw)
    ch = NotificationChannel(**base)
    db.add(ch)
    db.commit()
    db.refresh(ch)
    return ch


REPORT_BODY = {
    "name": "Nightly cert report",
    "report_type": "certificates",
    "filter_params": {},
    "format": "csv",
    "recipients": [],
    "cadence": "daily",
    "schedule_time": "08:00",
    "schedule_day": 0,
    "enabled": True,
}


def test_render_certificates_returns_csv_with_cert_columns(db):
    _cert(db)
    filename, csv_text = reports.render(db, "certificates", {})
    assert filename.startswith("certificates-")
    assert filename.endswith(".csv")
    header = csv_text.splitlines()[0]
    assert "common_name" in header
    assert "not_after" in header
    assert "example.com" in csv_text


def test_create_report_schedule_operator_ok_viewer_403(client, monkeypatch, db):
    ch = _channel(db)
    body = dict(REPORT_BODY, channel_id=ch.id)

    login_as(client, "viewer", monkeypatch)
    r = client.post("/api/reports", json=body)
    assert r.status_code == 403

    login_as(client, "operator", monkeypatch)
    r = client.post("/api/reports", json=body)
    assert r.status_code == 201, r.text
    created = r.json()
    assert created["name"] == "Nightly cert report"
    assert created["channel_id"] == ch.id

    r = client.get("/api/reports")
    assert r.status_code == 200
    items = r.json()
    items = items.get("items", items) if isinstance(items, dict) else items
    assert any(i["id"] == created["id"] for i in items)


def test_run_report_processes_through_worker_and_sends_email(client, monkeypatch, db):
    ch = _channel(db)
    _cert(db)
    body = dict(REPORT_BODY, channel_id=ch.id)

    login_as(client, "operator", monkeypatch)
    r = client.post("/api/reports", json=body)
    assert r.status_code == 201, r.text
    report_id = r.json()["id"]

    captured = {}

    def _fake_send_email(config, subject, body_text, body_html=None, attachments=None):
        captured["config"] = config
        captured["subject"] = subject
        captured["body_text"] = body_text
        captured["attachments"] = attachments

    monkeypatch.setattr(reports.notify, "send_email", _fake_send_email)

    r = client.post(f"/api/reports/{report_id}/run")
    assert r.status_code in (200, 202)
    assert r.json()["queued"] is True

    item = db.query(WorkQueue).filter_by(kind="report").one()
    assert item.payload["schedule_id"] == report_id

    processed = worker.process_one(db)
    assert processed is True

    db.refresh(item)
    assert item.status == "done"

    assert captured["attachments"] is not None
    assert len(captured["attachments"]) == 1
    fname, content = captured["attachments"][0]
    assert fname.startswith("certificates-")
    assert "example.com" in content
    assert captured["config"]["recipients"] == ["ops@example.com"]

    schedule = db.get(ReportSchedule, report_id)
    db.refresh(schedule)
    assert schedule.last_run_at is not None


def _schedule(**kw):
    from types import SimpleNamespace

    base = dict(cadence="daily", schedule_time="08:00", schedule_day=0, last_run_at=None)
    base.update(kw)
    return SimpleNamespace(**base)


def test_report_due_true_when_never_run():
    now = datetime(2026, 7, 1, 8, 5, tzinfo=timezone.utc)
    s = _schedule()
    assert report_due(s, now) is True


def test_report_due_false_when_already_run_in_window():
    now = datetime(2026, 7, 1, 8, 5, tzinfo=timezone.utc)
    s = _schedule(last_run_at=datetime(2026, 7, 1, 8, 1, tzinfo=timezone.utc))
    assert report_due(s, now) is False


def test_report_tick_enqueues_due_schedule_and_skips_not_due(db):
    from app import scheduler

    ch = _channel(db)
    due = ReportSchedule(
        name="due", report_type="certificates", cadence="daily", schedule_time="00:00",
        channel_id=ch.id, enabled=True, last_run_at=None,
    )
    not_due = ReportSchedule(
        name="not-due", report_type="certificates", cadence="daily", schedule_time="00:00",
        channel_id=ch.id, enabled=True, last_run_at=utcnow(),
    )
    db.add_all([due, not_due])
    db.commit()

    scheduler.report_tick()

    items = db.query(WorkQueue).filter_by(kind="report").all()
    schedule_ids = {i.payload["schedule_id"] for i in items}
    assert due.id in schedule_ids
    assert not_due.id not in schedule_ids
