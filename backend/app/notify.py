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


def send_email(config: dict, subject: str, body_text: str, body_html: str | None = None) -> None:
    """config keys: host, port, use_tls, use_starttls, username, password,
    from_address, recipients (list)."""
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


def send_webhook(config: dict, title: str, text: str, facts: dict | None = None, link: str = "") -> None:
    """Post to a Teams incoming webhook (MessageCard) or a generic JSON endpoint.

    config keys: url, format ('teams' | 'generic'). For 'generic' we POST a flat
    JSON object {title, text, facts, link}."""
    url = decrypt(config.get("url") or "")
    if not url:
        raise NotifyError("webhook URL not configured")

    if config.get("format", "teams") == "teams":
        payload = {
            "@type": "MessageCard",
            "@context": "http://schema.org/extensions",
            "themeColor": config.get("theme_color", "D7263D"),
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
