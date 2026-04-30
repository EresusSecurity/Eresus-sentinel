"""Splunk HTTP Event Collector (HEC) integration for Sentinel findings.

Ships findings and scan events to Splunk via HEC for SIEM correlation
and real-time alerting.

Usage:
    from sentinel.integrations.splunk import SplunkHECClient
    client = SplunkHECClient(
        url="https://splunk.example.com:8088",
        token="your-hec-token",
    )
    client.send_findings(findings, source="sentinel-scan")

Environment variables:
    SPLUNK_HEC_URL    — HEC endpoint URL
    SPLUNK_HEC_TOKEN  — HEC auth token
"""
from __future__ import annotations

import json
import logging
import os
import time
import urllib.request
from dataclasses import asdict
from typing import Any, Optional

logger = logging.getLogger(__name__)


class SplunkHECClient:
    """Send Sentinel findings to Splunk via HTTP Event Collector.

    Args:
        url: HEC endpoint URL (e.g. ``https://splunk:8088``).
        token: HEC authentication token.
        index: Target Splunk index (default: ``main``).
        source: Event source field (default: ``eresus-sentinel``).
        sourcetype: Event sourcetype (default: ``_json``).
        verify_ssl: Verify TLS certificates (default True).
        timeout: HTTP request timeout in seconds.
        batch_size: Maximum events per batch request.
    """

    def __init__(
        self,
        url: Optional[str] = None,
        token: Optional[str] = None,
        index: str = "main",
        source: str = "eresus-sentinel",
        sourcetype: str = "_json",
        verify_ssl: bool = True,
        timeout: int = 10,
        batch_size: int = 50,
    ) -> None:
        self._url = (url or os.environ.get("SPLUNK_HEC_URL", "")).rstrip("/")
        self._token = token or os.environ.get("SPLUNK_HEC_TOKEN", "")
        self._index = index
        self._source = source
        self._sourcetype = sourcetype
        self._verify_ssl = verify_ssl
        self._timeout = timeout
        self._batch_size = batch_size

    @property
    def available(self) -> bool:
        return bool(self._url and self._token)

    def send_findings(
        self,
        findings: list[Any],
        source: str = "",
        extra_fields: dict[str, Any] | None = None,
    ) -> int:
        """Send a list of Finding objects to Splunk.

        Returns the number of events successfully sent.
        """
        if not self.available:
            logger.debug("Splunk HEC not configured; skipping %d findings", len(findings))
            return 0

        events = []
        for f in findings:
            event_data = self._finding_to_dict(f)
            if extra_fields:
                event_data.update(extra_fields)
            events.append(self._wrap_event(event_data, source))

        return self._send_batch(events)

    def send_event(
        self,
        event_type: str,
        data: dict[str, Any],
        source: str = "",
    ) -> bool:
        """Send a single custom event."""
        if not self.available:
            return False
        payload = {"event_type": event_type, **data}
        wrapped = self._wrap_event(payload, source)
        return self._send_batch([wrapped]) > 0

    def _wrap_event(self, event_data: dict, source: str = "") -> dict:
        return {
            "time": time.time(),
            "host": os.uname().nodename if hasattr(os, "uname") else "unknown",
            "source": source or self._source,
            "sourcetype": self._sourcetype,
            "index": self._index,
            "event": event_data,
        }

    def _send_batch(self, events: list[dict]) -> int:
        sent = 0
        for i in range(0, len(events), self._batch_size):
            batch = events[i:i + self._batch_size]
            payload = "\n".join(json.dumps(e) for e in batch)
            try:
                self._post(payload)
                sent += len(batch)
            except Exception as exc:
                logger.error("Splunk HEC batch send failed: %s", exc)
        return sent

    def _post(self, payload: str) -> None:
        url = f"{self._url}/services/collector/event"
        req = urllib.request.Request(
            url,
            data=payload.encode("utf-8"),
            headers={
                "Authorization": f"Splunk {self._token}",
                "Content-Type": "application/json",
            },
            method="POST",
        )
        import ssl
        ctx = None
        if not self._verify_ssl:
            ctx = ssl.create_default_context()
            ctx.check_hostname = False
            ctx.verify_mode = ssl.CERT_NONE
        with urllib.request.urlopen(req, timeout=self._timeout, context=ctx) as resp:
            if resp.status != 200:
                body = resp.read().decode(errors="ignore")
                raise RuntimeError(f"HEC returned {resp.status}: {body}")

    @staticmethod
    def _finding_to_dict(finding: Any) -> dict:
        try:
            return asdict(finding)
        except (TypeError, AttributeError):
            result: dict[str, Any] = {}
            for attr in ("rule_id", "title", "description", "severity",
                         "confidence", "target", "module", "evidence"):
                val = getattr(finding, attr, None)
                if val is not None:
                    if hasattr(val, "value"):
                        val = val.value
                    result[attr] = val
            return result
