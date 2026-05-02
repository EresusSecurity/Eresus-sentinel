"""Notifier interface for scan completion and alert events."""
from __future__ import annotations

import json
import logging
import urllib.request
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any
from urllib.parse import urlparse

logger = logging.getLogger(__name__)


@dataclass
class Notification:
    title: str
    message: str
    severity: str = "info"
    source: str = "sentinel"
    metadata: dict[str, Any] = field(default_factory=dict)


class Notifier(ABC):
    """Abstract notifier interface."""

    @abstractmethod
    def send(self, notification: Notification) -> bool: ...


class LogNotifier(Notifier):
    """Logs notifications via Python logging."""

    def send(self, notification: Notification) -> bool:
        logger.info("[%s] %s: %s", notification.severity.upper(),
                    notification.title, notification.message)
        return True


class FileNotifier(Notifier):
    """Appends notifications to a JSONL file."""

    def __init__(self, path: str) -> None:
        self._path = path

    def send(self, notification: Notification) -> bool:
        try:
            with open(self._path, "a", encoding="utf-8") as f:
                f.write(json.dumps({
                    "title": notification.title,
                    "message": notification.message,
                    "severity": notification.severity,
                    "source": notification.source,
                    "metadata": notification.metadata,
                }) + "\n")
            return True
        except Exception as e:
            logger.warning("FileNotifier failed: %s", e)
            return False


class WebhookNotifier(Notifier):
    """Generic JSON webhook notifier."""

    def __init__(self, url: str = "", token: str = "", timeout: float = 5.0) -> None:
        self._url = url
        self._token = token
        self._timeout = timeout

    def send(self, notification: Notification) -> bool:
        if not self._url:
            logger.debug("Webhook URL not configured — skipping")
            return False
        parsed = urlparse(self._url)
        if parsed.scheme not in {"http", "https"}:
            logger.warning("Webhook URL must be http(s): %s", self._url)
            return False
        payload = json.dumps({
            "title": notification.title,
            "message": notification.message,
            "severity": notification.severity,
            "source": notification.source,
            "metadata": notification.metadata,
        }).encode("utf-8")
        headers = {"Content-Type": "application/json"}
        if self._token:
            headers["Authorization"] = f"Bearer {self._token}"
        req = urllib.request.Request(self._url, data=payload, headers=headers, method="POST")
        try:
            with urllib.request.urlopen(req, timeout=self._timeout) as response:
                return 200 <= getattr(response, "status", 200) < 300
        except Exception as exc:
            logger.warning("WebhookNotifier failed: %s", exc)
            return False


class NotifierChain:
    """Chain multiple notifiers together."""

    def __init__(self) -> None:
        self._notifiers: list[Notifier] = []

    def add(self, notifier: Notifier) -> None:
        self._notifiers.append(notifier)

    def send(self, notification: Notification) -> int:
        sent = 0
        for n in self._notifiers:
            try:
                if n.send(notification):
                    sent += 1
            except Exception as e:
                logger.warning("Notifier %s failed: %s", type(n).__name__, e)
        return sent

    @property
    def notifier_count(self) -> int:
        return len(self._notifiers)
