"""Webhook notifier — Slack/Discord/generic webhook integration."""

from __future__ import annotations

import json
import logging
import urllib.request
import urllib.error
from dataclasses import dataclass
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class NotificationPayload:
    title: str
    message: str
    severity: str = "INFO"
    fields: dict | None = None
    url: str = ""


class SlackNotifier:
    """Send fuzz results to Slack via incoming webhook."""

    SEVERITY_COLORS = {
        "CRITICAL": "#FF0000",
        "HIGH": "#FF6600",
        "MEDIUM": "#FFCC00",
        "LOW": "#00CC00",
        "INFO": "#0066FF",
    }

    def __init__(self, webhook_url: str):
        self._url = webhook_url

    def notify(self, payload: NotificationPayload) -> bool:
        color = self.SEVERITY_COLORS.get(payload.severity, "#808080")
        blocks = {
            "attachments": [{
                "color": color,
                "blocks": [
                    {
                        "type": "header",
                        "text": {"type": "plain_text", "text": f"🕷️ {payload.title}"},
                    },
                    {
                        "type": "section",
                        "text": {"type": "mrkdwn", "text": payload.message},
                    },
                ],
            }],
        }

        if payload.fields:
            fields_block = {
                "type": "section",
                "fields": [
                    {"type": "mrkdwn", "text": f"*{k}*\n{v}"}
                    for k, v in payload.fields.items()
                ],
            }
            blocks["attachments"][0]["blocks"].append(fields_block)

        return self._send(blocks)

    def notify_bypass(self, payload_name: str, category: str, severity: str, details: str = "") -> bool:
        return self.notify(NotificationPayload(
            title="Bypass Discovered",
            message=f"Payload `{payload_name}` bypassed scanner detection",
            severity=severity,
            fields={
                "Category": category,
                "Severity": severity,
                "Details": details or "N/A",
            },
        ))

    def notify_fuzz_summary(self, total: int, bypasses: int, crashes: int, tpr: float) -> bool:
        return self.notify(NotificationPayload(
            title="Fuzz Session Complete",
            message=f"Processed {total} payloads",
            severity="HIGH" if bypasses > 0 else "INFO",
            fields={
                "Total": str(total),
                "Bypasses": str(bypasses),
                "Crashes": str(crashes),
                "TPR": f"{tpr:.1%}",
            },
        ))

    def _send(self, payload: dict) -> bool:
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self._url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status == 200
        except Exception as exc:
            logger.error("Slack notification failed: %s", exc)
            return False


class DiscordNotifier:
    """Send fuzz results to Discord via webhook."""

    SEVERITY_COLORS = {
        "CRITICAL": 0xFF0000,
        "HIGH": 0xFF6600,
        "MEDIUM": 0xFFCC00,
        "LOW": 0x00CC00,
        "INFO": 0x0066FF,
    }

    def __init__(self, webhook_url: str):
        self._url = webhook_url

    def notify(self, payload: NotificationPayload) -> bool:
        color = self.SEVERITY_COLORS.get(payload.severity, 0x808080)
        embed = {
            "title": f"🕷️ {payload.title}",
            "description": payload.message,
            "color": color,
        }

        if payload.fields:
            embed["fields"] = [
                {"name": k, "value": str(v), "inline": True}
                for k, v in payload.fields.items()
            ]

        body = {"embeds": [embed]}
        return self._send(body)

    def notify_bypass(self, payload_name: str, category: str, severity: str, details: str = "") -> bool:
        return self.notify(NotificationPayload(
            title="Bypass Discovered",
            message=f"Payload `{payload_name}` bypassed scanner",
            severity=severity,
            fields={"Category": category, "Severity": severity, "Details": details or "N/A"},
        ))

    def _send(self, payload: dict) -> bool:
        try:
            data = json.dumps(payload).encode("utf-8")
            req = urllib.request.Request(
                self._url,
                data=data,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status in (200, 204)
        except Exception as exc:
            logger.error("Discord notification failed: %s", exc)
            return False


class GenericWebhookNotifier:
    """Send fuzz results to any HTTP webhook endpoint."""

    def __init__(self, webhook_url: str, headers: dict | None = None):
        self._url = webhook_url
        self._headers = headers or {}

    def notify(self, payload: NotificationPayload) -> bool:
        body = {
            "title": payload.title,
            "message": payload.message,
            "severity": payload.severity,
            "fields": payload.fields or {},
        }
        return self._send(body)

    def _send(self, payload: dict) -> bool:
        try:
            data = json.dumps(payload).encode("utf-8")
            headers = {"Content-Type": "application/json", **self._headers}
            req = urllib.request.Request(
                self._url, data=data, headers=headers, method="POST",
            )
            with urllib.request.urlopen(req, timeout=10) as resp:
                return 200 <= resp.status < 300
        except Exception as exc:
            logger.error("Webhook notification failed: %s", exc)
            return False
