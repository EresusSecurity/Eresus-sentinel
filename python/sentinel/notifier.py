"""Notifier interface for scan completion and alert events."""
from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any

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
    """Stub webhook notifier — disabled by default."""

    def __init__(self, url: str = "", token: str = "") -> None:
        self._url = url
        self._token = token

    def send(self, notification: Notification) -> bool:
        if not self._url:
            logger.debug("Webhook URL not configured — skipping")
            return False
        logger.debug("Would POST to %s: %s", self._url, notification.title)
        return True


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
