# ITSM / On-Call Channels — Paging + Chat (+ universal close-the-loop) — Design

**Phase:** 2.6, item 2.6.1 — first slice (see roadmap). ServiceNow/Jira ticketing
and Opsgenie are the NEXT cycle on this machinery.
**Date:** 2026-07-14
**Status:** Approved, ready for implementation planning.

## Goal

Add PagerDuty (on-call paging) and Slack (chat) notification channels, and — the
architectural heart — a **close-the-loop resolve path** so that when an alert
auto-resolves (cert renewed, scan recovered, CA renewed), channels are told it
cleared: PagerDuty auto-closes its incident, and message channels (Slack, **Teams**,
generic webhook, email) post a "Resolved" notice. Today resolution is silent —
`evaluate_alerts` flips `resolved=True` and dispatch simply stops re-notifying.

## Current architecture (reused)

- `NotificationChannel(channel_type, config JSON, enabled, re_alert_hours)`;
  `channel_type` is a free string. Secrets in `config` are encrypted
  (`secrets.encrypt/decrypt`) and scrubbed from API responses.
- `alerts.dispatch_alerts` iterates enabled channels per unresolved+unacked
  alert, calling `notify.send_email` (smtp) or `notify.send_webhook` (teams/generic).
- `alerts._format` builds subject/text/html/facts/link incl. owner/team,
  environment, severity, recommended action.
- `alerts.evaluate_alerts` reconciles desired vs stored alerts, sets
  `resolved=True` on stale ones, then calls `dispatch_alerts`.

## Scope

**In:** a universal resolve path (`dispatch_resolutions`) + `resolution_notified_at`
column; a per-channel `min_severity` filter; a PagerDuty channel (Events API
trigger/resolve via dedup_key); a Slack channel (webhook format variant);
"Resolved" notices for message channels including Teams; API + Settings UI for
the two new channel types.

**Out (deliberate ceilings):**
- Opsgenie, and ServiceNow/Jira ticketing (stateful, per-alert external-ref
  storage) — next cycle, same resolve-path machinery.
- A CertWatch **ack** does NOT close the PagerDuty incident (the condition still
  holds; only auto-resolve/renewal does). No PD "acknowledge" event.
- stdlib `urllib` for all senders (consistent with `notify.py`); no new dependency.

## Component 1 — universal close-the-loop resolve path

- **New column `AlertEvent.resolution_notified_at`** (nullable datetime),
  migration `0018` (head is `0017`). Marks that an alert's resolution has been
  dispatched, so it is sent exactly once.
- **New `alerts.dispatch_resolutions(db, now=None) -> int`:** select alerts where
  `resolved=True AND resolution_notified_at IS NULL AND notify_count > 0` (i.e.
  the alert was actually notified while open). For each, for each enabled channel
  passing the `min_severity` filter:
  - `pagerduty` → `send_pagerduty(event_action="resolve", dedup_key=ev.dedupe_key, ...)`
  - `smtp` → `send_email` with a resolved subject/body
  - `teams`/`webhook`/`slack` → `send_webhook` with a resolved message (positive
    styling: Teams green `themeColor`, Slack `good`/green color)
  Set `resolution_notified_at = now` after attempting all channels (a channel
  failure is logged, mirroring `dispatch_alerts`; the stamp still advances so a
  transient failure doesn't loop forever — `ponytail:` at-most-once resolve notice,
  not guaranteed delivery; the incident/message may be missed on a hard channel
  outage, acceptable for a courtesy "resolved" notice).
  Returns the count of alerts whose resolution was dispatched.
- **The resolve path does NOT skip acked or muted alerts** (unlike
  `dispatch_alerts`, which does). Once the underlying condition clears, closing an
  external incident / posting closure must happen regardless of local ack/mute — a
  PagerDuty incident locally acked in CertWatch still needs its `resolve` event when
  the cert actually renews. The `notify_count > 0` gate already ensures we only
  "resolve" alerts that were previously delivered.
- **Wire into `evaluate_alerts`:** after the reconcile loop and `db.commit()`,
  call `dispatch_resolutions(db, now)` alongside the existing `dispatch_alerts`
  (both gated by the `dispatch` flag).
- **Resolved-message formatting:** extend `_format` (or a small `_format_resolved`
  helper) to produce a subject like `[CertWatch RESOLVED] {rule_type} — {cn}` and
  a body noting the condition cleared, reusing the same facts.

**Behavior change (intended):** existing smtp/teams/generic-webhook channels now
also receive a one-time "Resolved" notice when an alert clears. This is the
close-the-loop the user requested for Teams; it applies uniformly. No per-channel
opt-out in v1 (`ponytail:` add a `notify_on_resolve` toggle only if someone wants
to suppress it).

## Component 2 — per-channel `min_severity` filter

- `config.min_severity` (one of `info|warning|critical`, absent = `info` = all).
- Helper `_severity_rank(s) -> int` (`info=0, warning=1, critical=2`); a channel is
  skipped for an alert when `rank(alert.severity) < rank(channel min_severity)`.
- Applied in BOTH `dispatch_alerts` and `dispatch_resolutions`.
- New PagerDuty channels default `min_severity="critical"` (set at creation in the
  UI/API default); other channel types default absent (all severities).

## Component 3 — PagerDuty channel (`channel_type="pagerduty"`)

- **`notify.send_pagerduty(config, event_action, dedup_key, summary, severity, link="")`:**
  POST JSON to `config.events_url` (default `https://events.pagerduty.com/v2/enqueue`)
  via stdlib `urllib` (as `send_webhook` does). Payload (Events API v2):
  ```json
  {"routing_key": "<decrypted secret>", "event_action": "trigger|resolve",
   "dedup_key": "<alert dedupe_key>",
   "payload": {"summary": "<summary>", "severity": "<mapped>",
               "source": "certwatch", "custom_details": {...facts, link}}}
  ```
  `resolve` events only need `routing_key`, `event_action`, `dedup_key`.
- **Secret:** `config.routing_key` (integration key), encrypted on write, scrubbed
  on read — same handling as the webhook `url`.
- **Severity mapping:** CertWatch `info|warning|critical` → PD `info|warning|critical`
  (all valid PD Events v2 values).
- **Trigger** on `dispatch_alerts` (dedup_key = `ev.dedupe_key`; PD dedups repeats,
  so re-alert re-triggering is harmless). **Resolve** on `dispatch_resolutions`
  (same dedup_key). No stored ref needed — the dedup_key is the linkage.
- Routing in the dispatch loop: `channel_type == "pagerduty"` → `send_pagerduty`.

## Component 4 — Slack channel (`channel_type="slack"`)

- Routed through `send_webhook` with a new `format="slack"` branch (per the
  roadmap: "a Slack format variant on the existing webhook sender"). Payload uses
  Slack `attachments`: `[{"color": <severity color>, "title": <subject>,
  "text": <message>, "fields": [{"title": k, "value": v, "short": true} ...],
  "title_link": <link>}]`.
- **Secret:** `config.url` (incoming-webhook URL), encrypted/scrubbed like the
  existing webhook.
- Severity colors: critical `#D7263D`, warning `#F59E0B`, info `#3B82F6`; resolved
  `#2EB67D` (green).
- Routing: `channel_type == "slack"` → `send_webhook` (which branches on the
  slack format). A resolved notice reuses the same path with the green color.

## Component 5 — API / Settings UI

- `POST/PUT /api/channels` and `POST /api/channels/{id}/test` accept
  `channel_type in {smtp, teams, webhook, slack, pagerduty}` (extend any existing
  allowed-type validation). Secret fields (`slack.url`, `pagerduty.routing_key`)
  encrypted on write, scrubbed on read (existing secret-handling path).
- **Test** action: Slack posts a test message; PagerDuty sends a `trigger` then a
  `resolve` (so the test doesn't leave a dangling incident) — or a low-severity
  test trigger with an immediate resolve.
- Settings page gains Slack and PagerDuty channel forms mirroring the Teams/webhook
  form, each with a `min_severity` selector (PagerDuty pre-set to `critical`).
- `re_alert_hours` and the resolve path interact unchanged (PD dedups repeats).

## Testing

Monkeypatch `urllib.request.urlopen` to capture POST (url, headers, body) without
network:
- **PagerDuty trigger** payload: correct `events_url`, `routing_key` (decrypted),
  `event_action="trigger"`, `dedup_key == ev.dedupe_key`, mapped `payload.severity`.
- **PagerDuty resolve** via `dispatch_resolutions`: `event_action="resolve"`, same
  dedup_key; sent exactly once (second `dispatch_resolutions` call is a no-op
  because `resolution_notified_at` is set); only for alerts with `notify_count > 0`.
- **Slack** payload: `attachments` shape, severity color, facts as fields.
- **Teams resolved notice**: `dispatch_resolutions` posts a MessageCard to a teams
  channel with the green `themeColor` and a resolved summary (the user's Teams ask).
- **min_severity filter**: a `warning` alert is skipped by a `critical`-only
  PagerDuty channel in both dispatch paths; an `info`-floor channel gets everything.
- **Secret scrubbing**: `routing_key` / slack `url` never appear in `GET /api/channels`.
- **No behavior regression**: existing smtp/teams/webhook trigger dispatch unchanged;
  resolved notices are additive and sent once.

## Files

- Create: migration `0018_alert_resolution_notified.py`, `backend/tests/test_pagerduty.py`,
  `backend/tests/test_slack.py`, `backend/tests/test_resolve_path.py`.
- Modify: `backend/app/models.py` (column), `backend/app/notify.py`
  (`send_pagerduty`, slack format in `send_webhook`, resolved helpers),
  `backend/app/alerts.py` (`dispatch_resolutions`, `min_severity` filter, dispatch
  routing, `evaluate_alerts` wiring, resolved `_format`), `backend/app/main.py`
  (channel type validation + test action), frontend Settings + `api.ts`, `README.md`.
