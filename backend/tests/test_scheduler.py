from datetime import datetime, timezone
from types import SimpleNamespace

from app.config import settings
from app.scheduler import schedule_due


def _t(**kw):
    base = dict(schedule_type="interval", scan_frequency_minutes=1440,
               schedule_time="00:00", schedule_day=0, last_scanned_at=None)
    base.update(kw)
    return SimpleNamespace(**base)


def _utc(y, mo, d, h, mi):
    return datetime(y, mo, d, h, mi, tzinfo=timezone.utc)


def test_interval():
    now = _utc(2026, 7, 1, 12, 0)
    assert schedule_due(_t(last_scanned_at=None), now) is True                 # never scanned
    assert schedule_due(_t(scan_frequency_minutes=60,
                           last_scanned_at=_utc(2026, 7, 1, 11, 30)), now) is False  # 30m ago
    assert schedule_due(_t(scan_frequency_minutes=60,
                           last_scanned_at=_utc(2026, 7, 1, 10, 30)), now) is True   # 90m ago


def test_daily_utc():
    settings.timezone = "UTC"
    now = _utc(2026, 7, 1, 8, 5)  # just after 08:00
    t = _t(schedule_type="daily", schedule_time="08:00")
    assert schedule_due(t, now) is True     # never scanned -> due
    t.last_scanned_at = _utc(2026, 7, 1, 7, 0)
    assert schedule_due(t, now) is True     # last scan was before today's window
    t.last_scanned_at = _utc(2026, 7, 1, 8, 1)
    assert schedule_due(t, now) is False    # already scanned inside this window


def test_daily_timezone_aware():
    settings.timezone = "America/New_York"   # summer -> EDT (UTC-4)
    now = _utc(2026, 7, 1, 12, 5)            # 08:05 EDT
    t = _t(schedule_type="daily", schedule_time="08:00",
           last_scanned_at=_utc(2026, 7, 1, 11, 0))  # 07:00 EDT, before window
    assert schedule_due(t, now) is True
    t.last_scanned_at = _utc(2026, 7, 1, 12, 2)       # 08:02 EDT, inside window
    assert schedule_due(t, now) is False
    settings.timezone = "UTC"


def test_weekly():
    settings.timezone = "UTC"
    now = _utc(2026, 7, 1, 10, 0)            # a Wednesday
    assert now.weekday() == 2
    due_today = _t(schedule_type="weekly", schedule_day=2, schedule_time="09:00",
                   last_scanned_at=_utc(2026, 6, 24, 9, 0))  # last Wed
    assert schedule_due(due_today, now) is True
    # scanned already this Wednesday -> not due
    due_today.last_scanned_at = _utc(2026, 7, 1, 9, 30)
    assert schedule_due(due_today, now) is False


def test_monthly():
    settings.timezone = "UTC"
    now = _utc(2026, 7, 15, 6, 0)
    t = _t(schedule_type="monthly", schedule_day=15, schedule_time="05:00",
           last_scanned_at=_utc(2026, 6, 15, 5, 0))   # last month's run
    assert schedule_due(t, now) is True
    t.last_scanned_at = _utc(2026, 7, 15, 5, 30)       # already ran this month
    assert schedule_due(t, now) is False
