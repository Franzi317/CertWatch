# ITSM Paging + Chat Channels Implementation Plan

> **For agentic workers:** REQUIRED SUB-SKILL: Use superpowers:subagent-driven-development (recommended) or superpowers:executing-plans to implement this plan task-by-task. Steps use checkbox (`- [ ]`) syntax for tracking.

**Goal:** Add PagerDuty (on-call paging) and Slack (chat) notification channels, plus a universal close-the-loop resolve path so every channel — including existing Teams/webhook/email — gets a "Resolved" notice when an alert clears (and PagerDuty auto-closes its incident).

**Architecture:** New `notify.send_pagerduty` (Events API v2 trigger/resolve via dedup_key) and a Slack `attachments` format in `notify.send_webhook`. `alerts.dispatch_alerts` gains channel-type routing + a per-channel `min_severity` filter. A new `alerts.dispatch_resolutions` (backed by an `AlertEvent.resolution_notified_at` column) fires once per resolved alert, wired into `evaluate_alerts` alongside the existing trigger dispatch. Channel secrets stay encrypted/scrubbed via the existing `_SECRET_KEYS` path.

**Tech Stack:** Python 3.13 / FastAPI / SQLAlchemy 2 / Alembic, stdlib `urllib` (no new dependency), React 18 + Vite, pytest.

## Global Constraints

- stdlib `urllib` for all senders (consistent with `notify.py`); NO new dependency.
- New `channel_type` values: `slack`, `pagerduty` (added to the existing free-string set `smtp|teams|webhook`). PagerDuty secret is `config.routing_key`; Slack secret is `config.url` (already handled). Both encrypted on write, scrubbed on read via `main.py`'s `_SECRET_KEYS`.
- PagerDuty uses the Events API v2 at `config.events_url` (default `https://events.pagerduty.com/v2/enqueue`); `dedup_key = alert.dedupe_key`; severity maps CertWatch `info|warning|critical` → PD `info|warning|critical` (all valid).
- New column `AlertEvent.resolution_notified_at` (nullable datetime), migration `0018` (head is `0017`).
- `dispatch_resolutions` selects `resolved=True AND resolution_notified_at IS NULL AND notify_count > 0`; it does NOT skip acked/muted alerts (closing an external incident must happen regardless of local ack/mute); it stamps `resolution_notified_at` after attempting all channels so a resolve is sent at most once.
- Per-channel `config.min_severity` (`info|warning|critical`, absent = `info` = all); a channel is skipped for an alert when `rank(alert.severity) < rank(channel min_severity)`. Applied in BOTH dispatch paths. New PagerDuty channels default `min_severity="critical"`.
- Existing smtp/teams/generic-webhook TRIGGER dispatch is unchanged; resolved notices are additive and sent once (intended behavior change: those channels now also get a one-time "Resolved" notice).
- `ponytail:` ceilings (preserve in comments): Opsgenie + ServiceNow/Jira ticketing are the next cycle; a CertWatch ack does NOT close the PD incident; at-most-once resolve notice (not guaranteed delivery).
- Test command (Windows, from `backend/`): `./.venv/Scripts/python.exe -m pytest`. Baseline: 310 passing.

---

### Task 1: `AlertEvent.resolution_notified_at` column + migration

**Files:**
- Modify: `backend/app/models.py` (`AlertEvent`, after `last_notified_at` ~line 178)
- Create: `backend/alembic/versions/0018_alert_resolution_notified.py`
- Test: `backend/tests/test_migrations.py` (verify still passes)

**Interfaces:**
- Produces: `AlertEvent.resolution_notified_at` (`datetime | None`, default None).

- [ ] **Step 1: Add the column**

In `backend/app/models.py`, in `class AlertEvent`, after `last_notified_at`:

```python
    # Set once dispatch_resolutions has notified channels that this alert cleared
    # (PagerDuty resolve event / "Resolved" message). NULL = resolution not yet
    # dispatched. Separate from resolved/updated_at so the resolve notice is sent
    # exactly once.
    resolution_notified_at: Mapped[datetime | None] = mapped_column(DateTime(timezone=True))
```

- [ ] **Step 2: Write the migration**

Confirm head is `0017` (`ls backend/alembic/versions/` — latest should be `0017_chain_ca_fingerprints.py`). Create `backend/alembic/versions/0018_alert_resolution_notified.py`:

```python
"""alert resolution notified

Revision ID: 0018
Revises: 0017
Create Date: 2026-07-14 00:00:00.000000

"""
from typing import Sequence, Union

import sqlalchemy as sa
from alembic import op

revision: str = '0018'
down_revision: Union[str, None] = '0017'
branch_labels: Union[str, Sequence[str], None] = None
depends_on: Union[str, Sequence[str], None] = None


def upgrade() -> None:
    op.add_column('alert_events', sa.Column('resolution_notified_at', sa.DateTime(timezone=True), nullable=True))


def downgrade() -> None:
    op.drop_column('alert_events', 'resolution_notified_at')
```

- [ ] **Step 3: Run the migration test**

Run: `cd backend && ./.venv/Scripts/python.exe -m pytest tests/test_migrations.py -v`
Expected: PASS.

- [ ] **Step 4: Commit**

```bash
git add backend/app/models.py backend/alembic/versions/0018_alert_resolution_notified.py
git commit -m "feat: add AlertEvent.resolution_notified_at column (close-the-loop)"
```

---

### Task 2: notify.py senders — `send_pagerduty` + Slack format

**Files:**
- Modify: `backend/app/notify.py` (`send_pagerduty`; `color` param + slack branch in `send_webhook`)
- Test: `backend/tests/test_notify_channels.py` (create)

**Interfaces:**
- Produces:
  - `notify.send_pagerduty(config, event_action, dedup_key, summary="", severity="critical", facts=None, link="") -> None`
  - `notify.send_webhook(config, title, text, facts=None, link="", color="") -> None` — now accepts an optional `color` (6-hex, no `#`) and a `format="slack"` branch.

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_notify_channels.py`:

```python
import json

import pytest

from app import notify
from app.notify import NotifyError


class _FakeResp:
    status = 202
    def __enter__(self): return self
    def __exit__(self, *a): return False


def _capture(monkeypatch):
    calls = []
    def fake_urlopen(req, timeout=15):
        calls.append({"url": req.full_url, "headers": dict(req.header_items()),
                      "body": json.loads(req.data.decode())})
        return _FakeResp()
    monkeypatch.setattr(notify.urllib.request, "urlopen", fake_urlopen)
    return calls


def test_pagerduty_trigger_payload(monkeypatch):
    calls = _capture(monkeypatch)
    # routing_key is stored encrypted; notify.decrypt is applied. Use a plaintext
    # value and monkeypatch decrypt to identity so the test needs no master key.
    monkeypatch.setattr(notify, "decrypt", lambda v: v)
    notify.send_pagerduty({"routing_key": "RK123"}, "trigger", "expiring:1:2:30",
                          summary="cert expiring", severity="warning",
                          facts={"Owner/team": "web"}, link="http://x/certificates/2")
    assert len(calls) == 1
    body = calls[0]["body"]
    assert calls[0]["url"] == "https://events.pagerduty.com/v2/enqueue"
    assert body["routing_key"] == "RK123"
    assert body["event_action"] == "trigger"
    assert body["dedup_key"] == "expiring:1:2:30"
    assert body["payload"]["severity"] == "warning"
    assert body["payload"]["source"] == "certwatch"


def test_pagerduty_resolve_minimal(monkeypatch):
    calls = _capture(monkeypatch)
    monkeypatch.setattr(notify, "decrypt", lambda v: v)
    notify.send_pagerduty({"routing_key": "RK"}, "resolve", "expiring:1:2:30")
    body = calls[0]["body"]
    assert body["event_action"] == "resolve"
    assert body["dedup_key"] == "expiring:1:2:30"
    assert "payload" not in body  # resolve needs only routing_key + dedup_key


def test_pagerduty_custom_events_url(monkeypatch):
    calls = _capture(monkeypatch)
    monkeypatch.setattr(notify, "decrypt", lambda v: v)
    notify.send_pagerduty({"routing_key": "RK", "events_url": "https://events.eu.pagerduty.com/v2/enqueue"},
                          "trigger", "k", summary="s")
    assert calls[0]["url"] == "https://events.eu.pagerduty.com/v2/enqueue"


def test_pagerduty_missing_routing_key_raises(monkeypatch):
    monkeypatch.setattr(notify, "decrypt", lambda v: v)
    with pytest.raises(NotifyError):
        notify.send_pagerduty({}, "trigger", "k", summary="s")


def test_slack_webhook_payload(monkeypatch):
    calls = _capture(monkeypatch)
    monkeypatch.setattr(notify, "decrypt", lambda v: v)
    notify.send_webhook({"url": "https://hooks.slack.com/x", "format": "slack"},
                        "Cert expiring", "body text", {"Owner/team": "web"},
                        "http://x/certificates/2", color="F59E0B")
    body = calls[0]["body"]
    assert "attachments" in body
    att = body["attachments"][0]
    assert att["color"] == "#F59E0B"
    assert att["title"] == "Cert expiring"
    assert any(f["title"] == "Owner/team" and f["value"] == "web" for f in att["fields"])


def test_teams_webhook_color_override(monkeypatch):
    calls = _capture(monkeypatch)
    monkeypatch.setattr(notify, "decrypt", lambda v: v)
    notify.send_webhook({"url": "https://teams/x", "format": "teams"},
                        "Resolved", "body", {}, "", color="2EB67D")
    body = calls[0]["body"]
    assert body["themeColor"] == "2EB67D"  # passed color overrides default red
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && ./.venv/Scripts/python.exe -m pytest tests/test_notify_channels.py -v`
Expected: FAIL — `send_pagerduty` doesn't exist; `send_webhook` doesn't accept `color`/slack.

- [ ] **Step 3: Implement `send_pagerduty`**

In `backend/app/notify.py`, add after `send_webhook`:

```python
_PAGERDUTY_DEFAULT_URL = "https://events.pagerduty.com/v2/enqueue"
# PagerDuty Events API v2 accepts these severities; CertWatch info|warning|critical all map 1:1.
_PD_SEVERITIES = {"critical", "error", "warning", "info"}


def send_pagerduty(config: dict, event_action: str, dedup_key: str,
                   summary: str = "", severity: str = "critical",
                   facts: dict | None = None, link: str = "") -> None:
    """POST a PagerDuty Events API v2 event. `event_action` is 'trigger' or
    'resolve'; a 'resolve' needs only routing_key + dedup_key (PD closes the
    incident matching that dedup_key). `config`: routing_key (secret, encrypted),
    events_url (optional; defaults to the US endpoint)."""
    routing_key = decrypt(config.get("routing_key") or "")
    if not routing_key:
        raise NotifyError("PagerDuty routing_key not configured")
    url = config.get("events_url") or _PAGERDUTY_DEFAULT_URL
    payload = {"routing_key": routing_key, "event_action": event_action, "dedup_key": dedup_key}
    if event_action == "trigger":
        payload["payload"] = {
            "summary": (summary or "CertWatch alert")[:1024],
            "severity": severity if severity in _PD_SEVERITIES else "critical",
            "source": "certwatch",
            "custom_details": {**(facts or {}), "link": link},
        }
    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 (trusted user-configured URL)
            if resp.status >= 300:
                raise NotifyError(f"PagerDuty returned HTTP {resp.status}")
    except urllib.error.URLError as e:
        raise NotifyError(f"PagerDuty send failed: {e}") from e
```

- [ ] **Step 4: Implement the `color` param + slack branch in `send_webhook`**

Replace `send_webhook`'s signature and body-construction so it accepts `color` and a `slack` format. The new signature:

```python
def send_webhook(config: dict, title: str, text: str, facts: dict | None = None,
                 link: str = "", color: str = "") -> None:
    """Post to a Teams incoming webhook (MessageCard), a Slack incoming webhook
    (attachments), or a generic JSON endpoint. config keys: url, format
    ('teams' | 'slack' | 'generic'). `color` is a 6-hex string (no '#'); when
    given it overrides the per-format default (used for severity coloring and the
    green 'resolved' notice)."""
    url = decrypt(config.get("url") or "")
    if not url:
        raise NotifyError("webhook URL not configured")

    fmt = config.get("format", "teams")
    if fmt == "teams":
        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": color or config.get("theme_color", "D7263D"),
            "summary": title,
            "sections": [{
                "activityTitle": title,
                "text": text,
                "facts": [{"name": k, "value": str(v)} for k, v in (facts or {}).items()],
            }],
            "potentialAction": (
                [{"@type": "OpenUri", "name": "View certificate",
                  "targets": [{"os": "default", "uri": link}]}] if link else []
            ),
        }
    elif fmt == "slack":
        payload = {"attachments": [{
            "color": f"#{color}" if color else "#D7263D",
            "title": title,
            "title_link": link or None,
            "text": text,
            "fields": [{"title": k, "value": str(v), "short": True} for k, v in (facts or {}).items()],
        }]}
    else:
        payload = {"title": title, "text": text, "facts": facts or {}, "link": link}

    data = json.dumps(payload).encode()
    req = urllib.request.Request(url, data=data, headers={"Content-Type": "application/json"})
    try:
        with urllib.request.urlopen(req, timeout=15) as resp:  # noqa: S310 (trusted user-configured URL)
            if resp.status >= 300:
                raise NotifyError(f"webhook returned HTTP {resp.status}")
    except urllib.error.URLError as e:
        raise NotifyError(f"webhook send failed: {e}") from e
```

Note: existing callers pass no `color`, so teams keeps its `D7263D` default and generic is unchanged — no regression.

- [ ] **Step 5: Run tests to verify they pass**

Run: `cd backend && ./.venv/Scripts/python.exe -m pytest tests/test_notify_channels.py tests/test_alerts.py -v`
Expected: PASS (new sender tests + existing alert tests unaffected).

- [ ] **Step 6: Commit**

```bash
git add backend/app/notify.py backend/tests/test_notify_channels.py
git commit -m "feat: send_pagerduty (Events API v2) + Slack webhook format + color param"
```

---

### Task 3: `min_severity` filter + trigger-path routing

**Files:**
- Modify: `backend/app/alerts.py` (import `send_pagerduty`; `_severity_rank`/`_severity_ok`/`_sev_color` helpers; route pagerduty/slack + apply filter in `dispatch_alerts`)
- Test: `backend/tests/test_channel_dispatch.py` (create)

**Interfaces:**
- Consumes: `notify.send_pagerduty` (Task 2).
- Produces: `alerts._severity_ok(channel, severity) -> bool`; `alerts._sev_color(severity) -> str`; `dispatch_alerts` routes `pagerduty` → `send_pagerduty("trigger", ...)`, `slack`/`teams`/`webhook` → `send_webhook(..., color=...)`, and skips channels below their `min_severity`.

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_channel_dispatch.py`:

```python
from app import alerts
from app.models import AlertEvent, Certificate, NotificationChannel, utcnow


def _cert(db):
    c = Certificate(fingerprint_sha256="FP:1", common_name="h.example.com", source="network")
    db.add(c); db.flush()
    return c


def _alert(db, severity="warning", rule="expiring"):
    c = _cert(db)
    ev = AlertEvent(dedupe_key=f"{rule}:1:{c.id}:30", certificate_id=c.id, rule_type=rule,
                    severity=severity, message="cert expiring", resolved=False)
    db.add(ev); db.commit()
    return ev


def _channel(db, ctype, **config):
    ch = NotificationChannel(name=f"{ctype}-ch", channel_type=ctype, enabled=True, config=config)
    db.add(ch); db.commit()
    return ch


def test_pagerduty_trigger_dispatched(db, monkeypatch):
    calls = []
    monkeypatch.setattr(alerts, "send_pagerduty",
                        lambda cfg, action, key, **kw: calls.append((action, key)))
    _channel(db, "pagerduty", routing_key="RK", min_severity="warning")
    ev = _alert(db, severity="warning")
    alerts.dispatch_alerts(db)
    assert calls == [("trigger", ev.dedupe_key)]


def test_pagerduty_critical_only_skips_warning(db, monkeypatch):
    calls = []
    monkeypatch.setattr(alerts, "send_pagerduty", lambda *a, **k: calls.append(1))
    _channel(db, "pagerduty", routing_key="RK", min_severity="critical")
    _alert(db, severity="warning")
    alerts.dispatch_alerts(db)
    assert calls == []  # warning below critical floor -> skipped


def test_slack_routed_through_webhook(db, monkeypatch):
    calls = []
    monkeypatch.setattr(alerts, "send_webhook",
                        lambda cfg, title, text, facts=None, link="", color="": calls.append(color))
    _channel(db, "slack", url="https://hooks.slack/x", format="slack")
    _alert(db, severity="critical")
    alerts.dispatch_alerts(db)
    assert len(calls) == 1 and calls[0]  # color passed (non-empty)
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && ./.venv/Scripts/python.exe -m pytest tests/test_channel_dispatch.py -v`
Expected: FAIL — `alerts.send_pagerduty` missing; pagerduty not routed; no min_severity filter.

- [ ] **Step 3: Implement helpers + routing**

In `backend/app/alerts.py`:

(a) Extend the notify import (find the existing `from .notify import ...`) to include `send_pagerduty`:

```python
from .notify import NotifyError, send_email, send_pagerduty, send_webhook
```

(b) Add helpers near the top (after `ONE_OFF_RULE_TYPES`):

```python
_SEVERITY_RANK = {"info": 0, "warning": 1, "critical": 2}
_SEVERITY_COLOR = {"info": "3B82F6", "warning": "F59E0B", "critical": "D7263D"}
_RESOLVED_COLOR = "2EB67D"


def _severity_ok(channel, severity: str) -> bool:
    floor = (channel.config or {}).get("min_severity") or "info"
    return _SEVERITY_RANK.get(severity, 0) >= _SEVERITY_RANK.get(floor, 0)


def _sev_color(severity: str) -> str:
    return _SEVERITY_COLOR.get(severity, "D7263D")
```

(c) In `dispatch_alerts`, replace the per-channel send block (the `if ch.channel_type == "smtp": ... else: send_webhook(...)`) with:

```python
        for ch in channels:
            if not _severity_ok(ch, ev.severity):
                continue
            try:
                if ch.channel_type == "smtp":
                    send_email(ch.config, subject, text, html)
                elif ch.channel_type == "pagerduty":
                    send_pagerduty(ch.config, "trigger", ev.dedupe_key,
                                   summary=subject, severity=ev.severity, facts=facts, link=link)
                else:  # teams | webhook | slack
                    send_webhook(ch.config, subject, text, facts, link, color=_sev_color(ev.severity))
                delivered = True
            except NotifyError as e:
                log.warning("channel %s failed for alert %s: %s", ch.name, ev.id, e)
```

- [ ] **Step 4: Run tests to verify they pass**

Run: `cd backend && ./.venv/Scripts/python.exe -m pytest tests/test_channel_dispatch.py tests/test_alerts.py -v`
Expected: PASS (existing alert tests still pass — smtp path and default teams color unchanged).

- [ ] **Step 5: Commit**

```bash
git add backend/app/alerts.py backend/tests/test_channel_dispatch.py
git commit -m "feat: min_severity filter + pagerduty/slack routing in dispatch_alerts"
```

---

### Task 4: resolve path — `dispatch_resolutions` + resolved formatting + wiring

**Files:**
- Modify: `backend/app/alerts.py` (`resolved` flag in `_format`; `dispatch_resolutions`; call it in `evaluate_alerts`)
- Test: `backend/tests/test_resolve_path.py` (create)

**Interfaces:**
- Consumes: `_format`, `_severity_ok`, `_RESOLVED_COLOR`, `send_email`/`send_webhook`/`send_pagerduty` (Tasks 2/3); `AlertEvent.resolution_notified_at` (Task 1).
- Produces: `alerts.dispatch_resolutions(db, now=None) -> int`; `evaluate_alerts` now returns an extra `resolution_notified` count.

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_resolve_path.py`:

```python
from app import alerts
from app.models import AlertEvent, Certificate, NotificationChannel, utcnow


def _resolved_alert(db, severity="critical", notify_count=1):
    c = Certificate(fingerprint_sha256="FP:R", common_name="h.example.com", source="network")
    db.add(c); db.flush()
    ev = AlertEvent(dedupe_key=f"expiring:1:{c.id}:30", certificate_id=c.id, rule_type="expiring",
                    severity=severity, message="cert expiring", resolved=True,
                    notify_count=notify_count)
    db.add(ev); db.commit()
    return ev


def _channel(db, ctype, **config):
    ch = NotificationChannel(name=f"{ctype}-ch", channel_type=ctype, enabled=True, config=config)
    db.add(ch); db.commit()
    return ch


def test_pagerduty_resolve_sent_once(db, monkeypatch):
    calls = []
    monkeypatch.setattr(alerts, "send_pagerduty",
                        lambda cfg, action, key, **kw: calls.append((action, key)))
    _channel(db, "pagerduty", routing_key="RK", min_severity="critical")
    ev = _resolved_alert(db)
    n = alerts.dispatch_resolutions(db)
    assert n == 1 and calls == [("resolve", ev.dedupe_key)]
    db.refresh(ev)
    assert ev.resolution_notified_at is not None
    # second call is a no-op (already notified)
    calls.clear()
    assert alerts.dispatch_resolutions(db) == 0 and calls == []


def test_resolve_skipped_when_never_notified(db, monkeypatch):
    calls = []
    monkeypatch.setattr(alerts, "send_pagerduty", lambda *a, **k: calls.append(1))
    _channel(db, "pagerduty", routing_key="RK")
    _resolved_alert(db, notify_count=0)  # never paged while open
    assert alerts.dispatch_resolutions(db) == 0 and calls == []


def test_teams_gets_resolved_messagecard(db, monkeypatch):
    calls = []
    monkeypatch.setattr(alerts, "send_webhook",
                        lambda cfg, title, text, facts=None, link="", color="": calls.append((title, color)))
    _channel(db, "teams", url="https://teams/x", format="teams")
    _resolved_alert(db)
    alerts.dispatch_resolutions(db)
    assert len(calls) == 1
    title, color = calls[0]
    assert "RESOLVED" in title and color == alerts._RESOLVED_COLOR


def test_resolve_ignores_ack_and_mute(db, monkeypatch):
    calls = []
    monkeypatch.setattr(alerts, "send_pagerduty", lambda cfg, action, key, **kw: calls.append(action))
    _channel(db, "pagerduty", routing_key="RK", min_severity="info")
    ev = _resolved_alert(db)
    ev.acknowledged = True
    ev.muted = True
    db.commit()
    assert alerts.dispatch_resolutions(db) == 1 and calls == ["resolve"]


def test_evaluate_alerts_reports_resolution_count(db, monkeypatch):
    monkeypatch.setattr(alerts, "send_pagerduty", lambda *a, **k: None)
    _channel(db, "pagerduty", routing_key="RK", min_severity="info")
    _resolved_alert(db)
    result = alerts.evaluate_alerts(db)
    assert result.get("resolution_notified") == 1
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && ./.venv/Scripts/python.exe -m pytest tests/test_resolve_path.py -v`
Expected: FAIL — `dispatch_resolutions` missing; `evaluate_alerts` result lacks `resolution_notified`.

- [ ] **Step 3: Add the `resolved` flag to `_format`**

In `backend/app/alerts.py`, change `_format(db, ev)` to `_format(db, ev, resolved: bool = False)` and update the subject + lead line (keep everything else):

```python
def _format(db: Session, ev: AlertEvent, resolved: bool = False):
    ...  # (unchanged up through building `facts`)
    tag = "RESOLVED" if resolved else ev.severity.upper()
    subject = f"[CertWatch {tag}] {ev.rule_type} — {cn or where}"
    lead = ("This condition has cleared (certificate renewed, scan recovered, or CA renewed). " + ev.message
            if resolved else ev.message)
    text_lines = [lead, "", *(f"{k}: {v}" for k, v in facts.items()), "",
                  f"Recommended action: {action}", f"Details: {link}"]
    text = "\n".join(text_lines)
    rows = "".join(f"<tr><td><b>{k}</b></td><td>{v}</td></tr>" for k, v in facts.items())
    html = (f"<h3>{subject}</h3><p>{lead}</p><table>{rows}</table>"
            f"<p><b>Recommended action:</b> {action}</p>"
            f"<p><a href='{link}'>View certificate detail</a></p>")
    return subject, text, html, facts, link
```

- [ ] **Step 4: Add `dispatch_resolutions`**

In `backend/app/alerts.py`, after `dispatch_alerts`:

```python
def dispatch_resolutions(db: Session, now: datetime | None = None) -> int:
    """Close-the-loop: for each alert that has resolved but whose resolution
    hasn't been announced, tell channels it cleared -- PagerDuty a 'resolve'
    event (auto-closes the incident), message channels a 'Resolved' notice.
    Stamped once via resolution_notified_at. Does NOT skip acked/muted alerts:
    closing an external incident must happen regardless of local ack/mute; the
    notify_count>0 gate limits this to alerts that were actually delivered."""
    now = now or utcnow()
    channels = db.scalars(select(NotificationChannel).where(NotificationChannel.enabled.is_(True))).all()
    if not channels:
        return 0
    pending = db.scalars(select(AlertEvent).where(
        AlertEvent.resolved.is_(True),
        AlertEvent.resolution_notified_at.is_(None),
        AlertEvent.notify_count > 0,
    )).all()
    sent = 0
    for ev in pending:
        subject, text, html, facts, link = _format(db, ev, resolved=True)
        for ch in channels:
            if not _severity_ok(ch, ev.severity):
                continue
            try:
                if ch.channel_type == "smtp":
                    send_email(ch.config, subject, text, html)
                elif ch.channel_type == "pagerduty":
                    send_pagerduty(ch.config, "resolve", ev.dedupe_key)
                else:  # teams | webhook | slack
                    send_webhook(ch.config, subject, text, facts, link, color=_RESOLVED_COLOR)
            except NotifyError as e:
                log.warning("resolve dispatch: channel %s failed for alert %s: %s", ch.name, ev.id, e)
        ev.resolution_notified_at = now
        sent += 1
    db.commit()
    return sent
```

- [ ] **Step 5: Wire into `evaluate_alerts`**

In `evaluate_alerts`, replace the final dispatch/return (the `sent = dispatch_alerts(...) ... return {...}` lines) with:

```python
    sent = dispatch_alerts(db, now) if dispatch else 0
    resolution_sent = dispatch_resolutions(db, now) if dispatch else 0
    return {"created": created, "resolved": resolved, "notified": sent,
            "resolution_notified": resolution_sent}
```

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd backend && ./.venv/Scripts/python.exe -m pytest tests/test_resolve_path.py tests/test_alerts.py tests/test_lifecycle_alerts.py -v`
Expected: PASS (existing alert/lifecycle-alert tests unaffected; `_format`'s default `resolved=False` preserves current output).

- [ ] **Step 7: Commit**

```bash
git add backend/app/alerts.py backend/tests/test_resolve_path.py
git commit -m "feat: universal close-the-loop resolve path (dispatch_resolutions)"
```

---

### Task 5: API — secret handling + test action for new channel types

**Files:**
- Modify: `backend/app/main.py` (`_SECRET_KEYS` add `routing_key`; `test_channel` routes pagerduty; channel-type comment), `backend/app/schemas.py` (comment)
- Test: `backend/tests/test_channels_api.py` (create)

**Interfaces:**
- Consumes: `send_pagerduty` (Task 2), existing channel routes.
- Produces: `routing_key` encrypted-on-write + scrubbed-on-read; `POST /api/channels/{id}/test` works for `pagerduty` and `slack`.

- [ ] **Step 1: Write the failing tests**

Create `backend/tests/test_channels_api.py`:

```python
def test_pagerduty_routing_key_scrubbed(client, monkeypatch):
    from tests.conftest import login_as
    login_as(client, "admin", monkeypatch)
    r = client.post("/api/channels", json={
        "name": "pd", "channel_type": "pagerduty", "enabled": True, "re_alert_hours": 24,
        "config": {"routing_key": "SECRET-RK", "min_severity": "critical"},
    })
    assert r.status_code == 201, r.text
    body = r.json()
    assert "routing_key" not in body["config"]  # scrubbed
    assert body["config"]["min_severity"] == "critical"  # non-secret kept
    # and it round-trips out of the list without the secret
    lst = client.get("/api/channels").json()
    assert all("routing_key" not in c["config"] for c in lst)


def test_test_channel_pagerduty(client, monkeypatch):
    from tests.conftest import login_as
    from app import main as app_main
    login_as(client, "operator", monkeypatch)
    calls = []
    monkeypatch.setattr(app_main, "send_pagerduty",
                        lambda cfg, action, key, **kw: calls.append(action))
    r = client.post("/api/channels", json={
        "name": "pd", "channel_type": "pagerduty", "enabled": True, "re_alert_hours": 24,
        "config": {"routing_key": "RK"},
    })
    cid = r.json()["id"]
    r = client.post(f"/api/channels/{cid}/test")
    assert r.status_code == 200, r.text
    # test sends a trigger then a resolve so it leaves no dangling incident
    assert calls == ["trigger", "resolve"]
```

- [ ] **Step 2: Run tests to verify they fail**

Run: `cd backend && ./.venv/Scripts/python.exe -m pytest tests/test_channels_api.py -v`
Expected: FAIL — `routing_key` not scrubbed (not in `_SECRET_KEYS`); test endpoint doesn't route pagerduty.

- [ ] **Step 3: Add `routing_key` to `_SECRET_KEYS`**

In `backend/app/main.py`:

```python
_SECRET_KEYS = {"password", "url", "routing_key"}
```

- [ ] **Step 4: Route the new types in `test_channel`**

In `test_channel`, replace the `if smtp / else send_webhook` with:

```python
    try:
        if ch.channel_type == "smtp":
            send_email(ch.config, "CertWatch test email",
                       "This is a test notification from CertWatch. SMTP is configured correctly.")
        elif ch.channel_type == "pagerduty":
            # trigger + immediate resolve so the test leaves no dangling incident
            send_pagerduty(ch.config, "trigger", f"certwatch-test-{ch.id}",
                           summary="CertWatch test alert", severity="info",
                           facts={"Channel": ch.name}, link=_base_url(db))
            send_pagerduty(ch.config, "resolve", f"certwatch-test-{ch.id}")
        else:  # teams | webhook | slack
            send_webhook(ch.config, "CertWatch test notification",
                         "This is a test notification from CertWatch. The webhook is configured correctly.",
                         {"Channel": ch.name}, _base_url(db))
```

Add `send_pagerduty` to `main.py`'s imports (find the existing `from .notify import send_email, send_webhook` and add it).

- [ ] **Step 5: Update the channel-type comment**

In `backend/app/schemas.py`, update the `ChannelIn.channel_type` comment to `# smtp | teams | webhook | slack | pagerduty`.

- [ ] **Step 6: Run tests to verify they pass**

Run: `cd backend && ./.venv/Scripts/python.exe -m pytest tests/test_channels_api.py tests/test_api.py -v`
Expected: PASS.

- [ ] **Step 7: Commit**

```bash
git add backend/app/main.py backend/app/schemas.py backend/tests/test_channels_api.py
git commit -m "feat: pagerduty routing_key secret handling + test action for slack/pagerduty"
```

---

### Task 6: Frontend channel forms + docs + full-suite verify

**Files:**
- Modify: `frontend/src/pages/Settings.tsx` (Slack + PagerDuty channel forms + min_severity selector), `frontend/src/api.ts` (channel type), `README.md`

**Interfaces:**
- Consumes: the channel API (Task 5) — `channel_type` `slack`/`pagerduty`, config `url`/`routing_key`/`min_severity`/`events_url`.

- [ ] **Step 1: Inspect the existing channel UI**

Read `frontend/src/pages/Settings.tsx` — specifically how the existing SMTP and Teams/webhook channel forms are structured (fields, the create/test/delete calls, how `config` is assembled), and `frontend/src/api.ts` for the channel create/update/test helpers and the channel type. Match these patterns exactly.

- [ ] **Step 2: Add Slack + PagerDuty forms**

In `Settings.tsx`, add two channel forms mirroring the Teams/webhook one:
- **Slack**: `channel_type: "slack"`, config `{ url, format: "slack", min_severity }`. Fields: webhook URL (secret; blank-on-edit keeps existing), min_severity selector (info/warning/critical, default blank = all).
- **PagerDuty**: `channel_type: "pagerduty"`, config `{ routing_key, events_url?, min_severity }`. Fields: routing/integration key (secret), optional events URL, min_severity selector defaulting to `critical`.
Each with the existing Test and Delete buttons wired to the channel endpoints.

- [ ] **Step 3: Update the api.ts channel type**

If `api.ts` has a channel-type union/type, widen it to include `"slack" | "pagerduty"`. If channel types are free strings there, no change — note it in the report.

- [ ] **Step 4: Build the frontend**

Run: `cd frontend && npm run build`
Expected: PASS (no type errors).

- [ ] **Step 5: Document in README**

In the "Configuring Teams / webhook" area, add short subsections: **Slack** (paste an incoming-webhook URL; choose severity floor) and **PagerDuty** (paste an Events API v2 integration/routing key; defaults to critical-only; auto-resolves the incident when the alert clears). Add one line to the alerting section noting that when an alert auto-resolves, all channels (including Teams/webhook/email) now receive a one-time "Resolved" notice.

- [ ] **Step 6: Run the full backend suite**

Run: `cd backend && ./.venv/Scripts/python.exe -m pytest -q`
Expected: PASS — 310 baseline + all new channel/resolve tests, green.

- [ ] **Step 7: Commit**

```bash
git add frontend/src README.md
git commit -m "feat: Slack + PagerDuty channel forms; document paging/chat + resolve notices"
```

---

## Self-Review Notes

- **Spec coverage:** resolution_notified_at column (T1); send_pagerduty + slack format + color (T2); min_severity filter + trigger routing (T3); dispatch_resolutions + resolved formatting + evaluate_alerts wiring + ack/mute-ignore + once-only (T4); routing_key secret + test action (T5); frontend forms + docs (T6). All spec sections mapped.
- **Ceilings preserved in comments:** Opsgenie/ticketing next cycle, ack doesn't close PD, at-most-once resolve, stdlib urllib (T2/T4 docstrings + Global Constraints).
- **Type consistency:** `send_pagerduty(config, event_action, dedup_key, summary=, severity=, facts=, link=)` identical across T2/T3/T5; `send_webhook(..., color="")` identical T2/T3/T4; `_severity_ok`/`_sev_color`/`_RESOLVED_COLOR` defined T3, reused T4; `dedup_key = ev.dedupe_key` consistent; `resolution_notified_at` consistent T1/T4; channel_type strings `slack`/`pagerduty` identical across T3/T5/T6.
- **No behavior regression flagged:** existing `send_webhook` callers pass no `color` (teams default red preserved); `_format` default `resolved=False` preserves current output; smtp path unchanged.
- **Open confirmations for the implementer (not blockers):** exact frontend channel-form/api.ts mechanism (T6 Step 1 resolves); that `0017` is the current alembic head (T1 Step 2 resolves).
```
