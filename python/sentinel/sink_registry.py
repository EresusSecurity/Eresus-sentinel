"""Audit sink registry — JSONL, Splunk, and OTLP sink stubs."""
from __future__ import annotations

import json
import logging
from abc import ABC, abstractmethod
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)


class AuditSink(ABC):
    """Abstract audit event sink."""

    @abstractmethod
    def emit(self, event: dict[str, Any]) -> None: ...

    def flush(self) -> None:
        pass

    def close(self) -> None:
        pass


class JSONLSink(AuditSink):
    """Write audit events to a JSONL file."""

    def __init__(self, path: Path) -> None:
        self._path = path
        self._file = open(path, "a", encoding="utf-8")

    def emit(self, event: dict[str, Any]) -> None:
        self._file.write(json.dumps(event) + "\n")

    def flush(self) -> None:
        self._file.flush()

    def close(self) -> None:
        self._file.close()


class LogSink(AuditSink):
    """Write audit events to Python logging."""

    def __init__(self, logger_name: str = "sentinel.audit") -> None:
        self._logger = logging.getLogger(logger_name)

    def emit(self, event: dict[str, Any]) -> None:
        self._logger.info("AUDIT: %s", json.dumps(event))


class SplunkSink(AuditSink):
    """Stub Splunk HEC sink — requires external configuration."""

    def __init__(self, hec_url: str = "", token: str = "") -> None:
        self._hec_url = hec_url
        self._token = token

    def emit(self, event: dict[str, Any]) -> None:
        if not self._hec_url:
            logger.debug("Splunk HEC URL not configured — skipping emit")
            return
        logger.debug("Would send to Splunk HEC: %s", self._hec_url)


class OTLPSink(AuditSink):
    """Stub OTLP exporter sink."""

    def __init__(self, endpoint: str = "") -> None:
        self._endpoint = endpoint

    def emit(self, event: dict[str, Any]) -> None:
        if not self._endpoint:
            logger.debug("OTLP endpoint not configured — skipping emit")
            return
        logger.debug("Would send to OTLP: %s", self._endpoint)


class SinkRegistry:
    """Registry of audit event sinks."""

    def __init__(self) -> None:
        self._sinks: dict[str, AuditSink] = {}

    def register(self, name: str, sink: AuditSink) -> None:
        self._sinks[name] = sink

    def emit(self, event: dict[str, Any]) -> None:
        for name, sink in self._sinks.items():
            try:
                sink.emit(event)
            except Exception as e:
                logger.warning("Sink '%s' failed: %s", name, e)

    def flush_all(self) -> None:
        for sink in self._sinks.values():
            sink.flush()

    def close_all(self) -> None:
        for sink in self._sinks.values():
            sink.close()

    @property
    def sink_count(self) -> int:
        return len(self._sinks)

    def sink_names(self) -> list[str]:
        return sorted(self._sinks.keys())
