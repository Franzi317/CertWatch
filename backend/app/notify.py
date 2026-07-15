"""Notification senders: SMTP email and Teams/generic webhook.

Uses the stdlib (`smtplib`, `urllib`) so there's no runtime HTTP dependency.
Secrets live in the channel `config` and are never logged or returned by the API.
"""
from __future__ import annotations

import json
import logging
import smtplib
import ssl
import urllib.request
from email.message import EmailMessage

from .secrets import decrypt

log = logging.getLogger("certwatch.notify")


class NotifyError(Exception):
    pass


def send_email(
    config: dict,
    subject: str,
    body_text: str,
    body_html: str | None = None,
    attachments: list[tuple[str, str]] | None = None,
) -> None:
    """config keys: host, port, use_tls, use_starttls, username, password,
    from_address, recipients (list).

    `attachments` (Phase 2, Task 5) is an optional list of (filename,
    text_content) pairs -- e.g. a scheduled report's CSV -- attached as
    text/csv parts. Defaults to None so existing callers are unaffected.
    """
    host = config.get("host")
    port = int(config.get("port", 587))
    recipients = config.get("recipients") or []
    if not host:
        raise NotifyError("SMTP host not configured")
    if not recipients:
        raise NotifyError("no recipients configured")

    msg = EmailMessage()
    msg["Subject"] = subject
    msg["From"] = config.get("from_address", "certwatch@localhost")
    msg["To"] = ", ".join(recipients)
    msg.set_content(body_text)
    if body_html:
        msg.add_alternative(body_html, subtype="html")
    for fname, content in (attachments or []):
        msg.add_attachment(content.encode(), maintype="text", subtype="csv", filename=fname)

    context = ssl.create_default_context()
    try:
        if config.get("use_tls"):
            server = smtplib.SMTP_SSL(host, port, timeout=15, context=context)
        else:
            server = smtplib.SMTP(host, port, timeout=15)
        with server:
            if config.get("use_starttls") and not config.get("use_tls"):
                server.starttls(context=context)
            if config.get("username"):
                server.login(config["username"], decrypt(config.get("password", "")))
            server.send_message(msg)
    except (smtplib.SMTPException, OSError) as e:
        raise NotifyError(f"SMTP send failed: {e}") from e


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
            "themeColor": config.get("theme_color") or color or "D7263D",
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
