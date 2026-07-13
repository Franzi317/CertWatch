import datetime

from app import scheduler
from app.models import WatchedDomain, WorkQueue, utcnow


def _watched(db, **kw):
    w = WatchedDomain(domain=kw.pop("domain", "example.com"), enabled=kw.pop("enabled", True), **kw)
    db.add(w); db.commit()
    return w


def test_ct_tick_enqueues_due_domain(db, monkeypatch):
    monkeypatch.setattr(scheduler.settings, "ct_source_url", "https://crt.sh", raising=False)
    monkeypatch.setattr(scheduler, "SessionLocal", lambda: db)
    _watched(db, last_checked_at=None)
    scheduler.ct_tick()
    assert db.query(WorkQueue).filter_by(kind="ct_check").count() == 1


def test_ct_tick_skips_recently_checked(db, monkeypatch):
    monkeypatch.setattr(scheduler.settings, "ct_source_url", "https://crt.sh", raising=False)
    monkeypatch.setattr(scheduler.settings, "ct_check_frequency_hours", 24, raising=False)
    monkeypatch.setattr(scheduler, "SessionLocal", lambda: db)
    _watched(db, last_checked_at=utcnow() - datetime.timedelta(hours=1))
    scheduler.ct_tick()
    assert db.query(WorkQueue).filter_by(kind="ct_check").count() == 0


def test_ct_tick_noop_when_disabled(db, monkeypatch):
    monkeypatch.setattr(scheduler.settings, "ct_source_url", "", raising=False)
    monkeypatch.setattr(scheduler, "SessionLocal", lambda: db)
    _watched(db, last_checked_at=None)
    scheduler.ct_tick()
    assert db.query(WorkQueue).filter_by(kind="ct_check").count() == 0


def test_ct_tick_skips_domain_with_inflight_item(db, monkeypatch):
    monkeypatch.setattr(scheduler.settings, "ct_source_url", "https://crt.sh", raising=False)
    monkeypatch.setattr(scheduler, "SessionLocal", lambda: db)
    w = _watched(db, last_checked_at=None)
    db.add(WorkQueue(kind="ct_check", payload={"domain_id": w.id}, status="queued"))
    db.commit()
    scheduler.ct_tick()
    assert db.query(WorkQueue).filter_by(kind="ct_check").count() == 1  # not duplicated
