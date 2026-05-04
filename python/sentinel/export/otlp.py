"""OpenTelemetry OTLP/HTTP JSON export for Sentinel findings and events."""

from __future__ import annotations

import json
import os
import time
import urllib.request
from dataclasses import asdict, dataclass
from datetime import datetime
from typing import Any, cast
from urllib.parse import parse_qsl, urlparse

_SEVERITY_NUMBER = {
    "critical": 17,
    "high": 17,
    "medium": 13,
    "low": 9,
    "info": 9,
}


@dataclass
class ExportResult:
    """Result returned by runtime exporters."""

    backend: str
    configured: bool
    sent: int
    endpoint: str = ""
    error: str = ""

    def to_dict(self) -> dict[str, Any]:
        return asdict(self)


class OTLPExporter:
    """Export Sentinel findings/events as OTLP HTTP JSON log records.

    Environment variables:
      - ``SENTINEL_OTLP_ENDPOINT`` or ``OTEL_EXPORTER_OTLP_LOGS_ENDPOINT``
      - ``OTEL_EXPORTER_OTLP_ENDPOINT`` as a base endpoint fallback
      - ``SENTINEL_OTLP_HEADERS`` or ``OTEL_EXPORTER_OTLP_HEADERS`` for
        comma-separated ``key=value`` request headers.
    """

    def __init__(
        self,
        endpoint: str | None = None,
        headers: dict[str, str] | None = None,
        service_name: str = "eresus-sentinel",
        timeout: float = 10.0,
    ) -> None:
        self.endpoint = endpoint or _resolve_endpoint()
        self.headers = headers or _resolve_headers()
        self.service_name = service_name
        self.timeout = timeout

    @property
    def configured(self) -> bool:
        return bool(self.endpoint)

    def build_payload(
        self,
        findings: list[Any] | None = None,
        *,
        events: list[dict[str, Any]] | None = None,
        scan_id: str = "",
    ) -> dict[str, Any]:
        """Build an OTLP/HTTP JSON payload without sending it."""

        records = []
        now_ns = int(time.time() * 1_000_000_000)
        for finding in findings or []:
            item = _finding_to_dict(finding)
            timestamp_ns = _timestamp_ns(item.get("timestamp")) or now_ns
            severity = str(item.get("severity", "info")).lower()
            records.append(
                {
                    "timeUnixNano": str(timestamp_ns),
                    "severityText": severity.upper(),
                    "severityNumber": _SEVERITY_NUMBER.get(severity, 9),
                    "body": {"stringValue": json.dumps(item, sort_keys=True, default=str)},
                    "attributes": _attributes(
                        {
                            "sentinel.type": "finding",
                            "sentinel.rule_id": item.get("rule_id", ""),
                            "sentinel.module": item.get("module", ""),
                            "sentinel.severity": severity,
                            "sentinel.target": item.get("target", ""),
                            "sentinel.fingerprint": item.get("fingerprint", ""),
                            "sentinel.scan_id": scan_id or item.get("scan_id", ""),
                        }
                    ),
                }
            )

        for event in events or []:
            records.append(
                {
                    "timeUnixNano": str(_event_time_ns(event) or now_ns),
                    "severityText": str(event.get("severity", "INFO")).upper(),
                    "severityNumber": _SEVERITY_NUMBER.get(
                        str(event.get("severity", "info")).lower(),
                        9,
                    ),
                    "body": {"stringValue": json.dumps(event, sort_keys=True, default=str)},
                    "attributes": _attributes(
                        {
                            "sentinel.type": "event",
                            "sentinel.event_type": event.get("event_type", event.get("type", "")),
                            "sentinel.scan_id": scan_id or event.get("scan_id", ""),
                        }
                    ),
                }
            )

        return {
            "resourceLogs": [
                {
                    "resource": {
                        "attributes": _attributes(
                            {
                                "service.name": self.service_name,
                                "telemetry.sdk.language": "python",
                                "sentinel.exporter": "otlp",
                            }
                        )
                    },
                    "scopeLogs": [
                        {
                            "scope": {"name": "sentinel.export.otlp"},
                            "logRecords": records,
                        }
                    ],
                }
            ]
        }

    def render(self, findings: list[Any], *, scan_id: str = "") -> str:
        """Render findings as pretty OTLP JSON."""

        return json.dumps(self.build_payload(findings, scan_id=scan_id), indent=2, default=str)

    def render_events(self, events: list[dict[str, Any]], *, scan_id: str = "") -> str:
        """Render raw audit/runtime events as pretty OTLP JSON."""

        return json.dumps(self.build_payload(events=events, scan_id=scan_id), indent=2, default=str)

    def export_findings(self, findings: list[Any], *, scan_id: str = "") -> ExportResult:
        """POST findings to the configured OTLP HTTP logs endpoint."""

        payload = self.build_payload(findings, scan_id=scan_id)
        return self._post(payload, len(findings))

    def export_events(self, events: list[dict[str, Any]], *, scan_id: str = "") -> ExportResult:
        """POST raw audit/runtime events to the configured OTLP HTTP logs endpoint."""

        payload = self.build_payload(events=events, scan_id=scan_id)
        return self._post(payload, len(events))

    def _post(self, payload: dict[str, Any], count: int) -> ExportResult:
        if not self.endpoint:
            return ExportResult("otlp", configured=False, sent=0)

        body = json.dumps(payload, default=str).encode("utf-8")
        request_headers = {"Content-Type": "application/json", **self.headers}
        request = urllib.request.Request(  # noqa: S310
            _logs_endpoint(self.endpoint),
            data=body,
            headers=request_headers,
            method="POST",
        )
        try:
            with urllib.request.urlopen(request, timeout=self.timeout) as response:  # noqa: S310
                if response.status >= 400:
                    return ExportResult(
                        "otlp",
                        configured=True,
                        sent=0,
                        endpoint=self.endpoint,
                        error=f"HTTP {response.status}",
                    )
            return ExportResult("otlp", configured=True, sent=count, endpoint=self.endpoint)
        except Exception as exc:  # noqa: BLE001
            return ExportResult(
                "otlp",
                configured=True,
                sent=0,
                endpoint=self.endpoint,
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


def _attributes(values: dict[str, Any]) -> list[dict[str, Any]]:
    attrs = []
    for key, value in values.items():
        if value is None or value == "":
            continue
        attrs.append({"key": key, "value": {"stringValue": str(value)}})
    return attrs


def _timestamp_ns(value: Any) -> int:
    if not value:
        return 0
    if isinstance(value, (int, float)):
        return int(float(value) * 1_000_000_000)
    try:
        text = str(value).replace("Z", "+00:00")
        return int(datetime.fromisoformat(text).timestamp() * 1_000_000_000)
    except ValueError:
        return 0


def _event_time_ns(event: dict[str, Any]) -> int:
    for key in ("timestamp", "time", "created_at"):
        if key in event:
            return _timestamp_ns(event[key])
    return 0


def _resolve_endpoint() -> str:
    return (
        os.environ.get("SENTINEL_OTLP_ENDPOINT")
        or os.environ.get("OTEL_EXPORTER_OTLP_LOGS_ENDPOINT")
        or os.environ.get("OTEL_EXPORTER_OTLP_ENDPOINT")
        or ""
    )


def _resolve_headers() -> dict[str, str]:
    raw = (
        os.environ.get("SENTINEL_OTLP_HEADERS")
        or os.environ.get("OTEL_EXPORTER_OTLP_HEADERS")
        or ""
    )
    if not raw:
        return {}
    return dict(parse_qsl(raw.replace(",", "&"), keep_blank_values=True))


def _logs_endpoint(endpoint: str) -> str:
    parsed = urlparse(endpoint)
    if parsed.path.endswith("/v1/logs"):
        return endpoint
    return endpoint.rstrip("/") + "/v1/logs"
