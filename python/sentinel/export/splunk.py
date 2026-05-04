"""Splunk HTTP Event Collector export for Sentinel findings and events."""

from __future__ import annotations

import json
import os
import socket
import time
import urllib.request
from dataclasses import asdict, dataclass
from typing import Any, cast

from sentinel.export.otlp import ExportResult


@dataclass
class SplunkHECConfig:
    """Connection settings for Splunk HTTP Event Collector."""

    url: str = ""
    token: str = ""
    index: str = "main"
    source: str = "eresus-sentinel"
    sourcetype: str = "sentinel:finding"
    timeout: float = 10.0


class SplunkHECExporter:
    """Export Sentinel findings/events to Splunk HEC JSON events."""

    def __init__(
        self,
        url: str | None = None,
        token: str | None = None,
        index: str | None = None,
        source: str = "eresus-sentinel",
        sourcetype: str = "sentinel:finding",
        timeout: float = 10.0,
    ) -> None:
        self.config = SplunkHECConfig(
            url=(url or os.environ.get("SPLUNK_HEC_URL", "")).rstrip("/"),
            token=token or os.environ.get("SPLUNK_HEC_TOKEN", ""),
            index=index or os.environ.get("SPLUNK_HEC_INDEX", "main"),
            source=source,
            sourcetype=sourcetype,
            timeout=timeout,
        )

    @property
    def configured(self) -> bool:
        return bool(self.config.url and self.config.token)

    def build_events(
        self,
        findings: list[Any] | None = None,
        *,
        events: list[dict[str, Any]] | None = None,
        scan_id: str = "",
    ) -> list[dict[str, Any]]:
        """Build HEC event envelopes without sending them."""

        envelopes: list[dict[str, Any]] = []
        for finding in findings or []:
            item = _finding_to_dict(finding)
            if scan_id and not item.get("scan_id"):
                item["scan_id"] = scan_id
            envelopes.append(self._wrap_event(item, sourcetype="sentinel:finding"))

        for event in events or []:
            item = dict(event)
            if scan_id and not item.get("scan_id"):
                item["scan_id"] = scan_id
            envelopes.append(self._wrap_event(item, sourcetype="sentinel:event"))

        return envelopes

    def render(self, findings: list[Any], *, scan_id: str = "") -> str:
        """Render findings as Splunk HEC JSON lines."""

        return "\n".join(
            json.dumps(event, sort_keys=True, default=str)
            for event in self.build_events(findings, scan_id=scan_id)
        )

    def render_events(self, events: list[dict[str, Any]], *, scan_id: str = "") -> str:
        """Render raw audit/runtime events as Splunk HEC JSON lines."""

        return "\n".join(
            json.dumps(event, sort_keys=True, default=str)
            for event in self.build_events(events=events, scan_id=scan_id)
        )

    def export_findings(self, findings: list[Any], *, scan_id: str = "") -> ExportResult:
        """POST findings to the configured Splunk HEC endpoint."""

        return self._post(self.build_events(findings, scan_id=scan_id), len(findings))

    def export_events(self, events: list[dict[str, Any]], *, scan_id: str = "") -> ExportResult:
        """POST raw audit/runtime events to the configured Splunk HEC endpoint."""

        return self._post(self.build_events(events=events, scan_id=scan_id), len(events))

    def _wrap_event(self, event: dict[str, Any], *, sourcetype: str) -> dict[str, Any]:
        return {
            "time": _event_time(event),
            "host": socket.gethostname(),
            "source": self.config.source,
            "sourcetype": sourcetype or self.config.sourcetype,
            "index": self.config.index,
            "event": event,
        }

    def _post(self, events: list[dict[str, Any]], count: int) -> ExportResult:
        if not self.config.url or not self.config.token:
            return ExportResult("splunk", configured=False, sent=0)

        body = "\n".join(json.dumps(event, default=str) for event in events).encode("utf-8")
        request = urllib.request.Request(  # noqa: S310
            self.config.url.rstrip("/") + "/services/collector/event",
            data=body,
            headers={
                "Authorization": f"Splunk {self.config.token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.config.timeout) as response:  # noqa: S310
                if response.status >= 400:
                    return ExportResult(
                        "splunk",
                        configured=True,
                        sent=0,
                        endpoint=self.config.url,
                        error=f"HTTP {response.status}",
                    )
            return ExportResult("splunk", configured=True, sent=count, endpoint=self.config.url)
        except Exception as exc:  # noqa: BLE001
            return ExportResult(
                "splunk",
                configured=True,
                sent=0,
                endpoint=self.config.url,
                error=str(exc),
            )


def _finding_to_dict(finding: Any) -> dict[str, Any]:
    if hasattr(finding, "to_dict"):
        return cast("dict[str, Any]", finding.to_dict())
    if isinstance(finding, dict):
        return dict(finding)
    try:
        return asdict(finding)
    except (TypeError, ValueError):
        return {
            key: getattr(finding, key)
            for key in ("rule_id", "module", "title", "description", "severity", "target")
            if hasattr(finding, key)
        }


def _event_time(event: dict[str, Any]) -> float:
    value = event.get("timestamp") or event.get("time")
    if isinstance(value, (int, float)):
        return float(value)
    return time.time()
