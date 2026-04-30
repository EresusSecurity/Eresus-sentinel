"""LLM Gateway — reverse proxy for intercepting and inspecting LLM API calls.

Supports OpenAI, Anthropic, and generic chat completion APIs.
Applies firewall rules, audit logging, and guardrail verdicts.
"""

from __future__ import annotations

import json
import logging
import time
import uuid
from dataclasses import dataclass, field
from typing import Callable

logger = logging.getLogger(__name__)


@dataclass
class GatewayEvent:
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: float = field(default_factory=time.time)
    provider: str = ""
    model: str = ""
    messages: list[dict] = field(default_factory=list)
    response: str = ""
    latency_ms: float = 0.0
    verdict: str = "pass"
    blocked: bool = False
    guardrail_results: dict = field(default_factory=dict)
    metadata: dict = field(default_factory=dict)


@dataclass
class GuardrailVerdict:
    rule_name: str
    passed: bool
    score: float = 0.0
    details: str = ""


class AuditSink:
    """Base class for audit event sinks."""

    def emit(self, event: GatewayEvent) -> None:
        raise NotImplementedError


class JSONLFileSink(AuditSink):
    def __init__(self, path: str = "audit.jsonl"):
        self.path = path

    def emit(self, event: GatewayEvent) -> None:
        import dataclasses
        with open(self.path, "a") as f:
            f.write(json.dumps(dataclasses.asdict(event), default=str) + "\n")


class OTLPLogSink(AuditSink):
    def __init__(self, endpoint: str = "http://localhost:4317"):
        self.endpoint = endpoint

    def emit(self, event: GatewayEvent) -> None:
        try:
            import dataclasses

            import httpx
            payload = {"resourceLogs": [{"scopeLogs": [{"logRecords": [{"body": {"stringValue": json.dumps(dataclasses.asdict(event), default=str)}, "timeUnixNano": int(event.timestamp * 1e9), "severityText": "WARN" if event.blocked else "INFO"}]}]}]}
            httpx.post(f"{self.endpoint}/v1/logs", json=payload, timeout=5)
        except Exception as e:
            logger.warning("OTLP sink error: %s", e)


class SplunkHECSink(AuditSink):
    def __init__(self, url: str = "", token: str = ""):
        self.url = url
        self.token = token

    def emit(self, event: GatewayEvent) -> None:
        try:
            import dataclasses

            import httpx
            payload = {"event": dataclasses.asdict(event), "sourcetype": "sentinel:gateway", "time": event.timestamp}
            httpx.post(self.url, json=payload, headers={"Authorization": f"Splunk {self.token}"}, timeout=5)
        except Exception as e:
            logger.warning("Splunk HEC sink error: %s", e)


class WebhookSink(AuditSink):
    def __init__(self, url: str = "", headers: dict | None = None):
        self.url = url
        self.headers = headers or {}

    def emit(self, event: GatewayEvent) -> None:
        try:
            import dataclasses

            import httpx
            httpx.post(self.url, json=dataclasses.asdict(event), headers=self.headers, timeout=5)
        except Exception as e:
            logger.warning("Webhook sink error: %s", e)


class KillSwitch:
    """JSONL-based kill switch — if active, blocks all requests."""

    def __init__(self, path: str = ".sentinel_killswitch"):
        self.path = path

    def is_active(self) -> bool:
        import os
        return os.path.exists(self.path)

    def activate(self, reason: str = "") -> None:
        with open(self.path, "w") as f:
            f.write(json.dumps({"active": True, "reason": reason, "timestamp": time.time()}))

    def deactivate(self) -> None:
        import os
        if os.path.exists(self.path):
            os.remove(self.path)


class LLMGateway:
    """Reverse proxy gateway for LLM API calls with security inspection."""

    def __init__(self) -> None:
        self.guardrails: list[Callable[[list[dict], str], GuardrailVerdict]] = []
        self.sinks: list[AuditSink] = []
        self.kill_switch = KillSwitch()
        self._verdict_cache: dict[str, GuardrailVerdict] = {}

    def add_guardrail(self, fn: Callable[[list[dict], str], GuardrailVerdict]) -> None:
        self.guardrails.append(fn)

    def add_sink(self, sink: AuditSink) -> None:
        self.sinks.append(sink)

    def inspect(self, messages: list[dict], response: str, provider: str = "", model: str = "") -> GatewayEvent:
        event = GatewayEvent(provider=provider, model=model, messages=messages, response=response)

        if self.kill_switch.is_active():
            event.blocked = True
            event.verdict = "killed"
            self._emit(event)
            return event

        for guardrail in self.guardrails:
            try:
                verdict = guardrail(messages, response)
                event.guardrail_results[verdict.rule_name] = {"passed": verdict.passed, "score": verdict.score, "details": verdict.details}
                if not verdict.passed:
                    event.blocked = True
                    event.verdict = f"blocked:{verdict.rule_name}"
            except Exception as e:
                logger.error("Guardrail %s error: %s", guardrail, e)

        if not event.blocked:
            event.verdict = "pass"

        self._emit(event)
        return event

    def _emit(self, event: GatewayEvent) -> None:
        for sink in self.sinks:
            try:
                sink.emit(event)
            except Exception as e:
                logger.error("Sink error: %s", e)


# ── Daemon / Watchdog ──

class SentinelDaemon:
    """Background daemon for continuous LLM monitoring."""

    def __init__(self, gateway: LLMGateway | None = None):
        self.gateway = gateway or LLMGateway()
        self.running = False
        self._watched_files: list[str] = []

    def start(self) -> None:
        self.running = True
        logger.info("Sentinel daemon started")

    def stop(self) -> None:
        self.running = False
        logger.info("Sentinel daemon stopped")

    def watch_policy_file(self, path: str) -> None:
        self._watched_files.append(path)

    def check_policy_changes(self) -> list[str]:
        import os
        changed = []
        for path in self._watched_files:
            if os.path.exists(path):
                changed.append(path)
        return changed


class FileWatcher:
    """Watches files for changes and triggers rescans."""

    def __init__(self, paths: list[str] | None = None, callback: Callable[[str], None] | None = None):
        self.paths = paths or []
        self.callback = callback
        self._mtimes: dict[str, float] = {}

    def scan(self) -> list[str]:
        import os
        changed: list[str] = []
        for path in self.paths:
            if not os.path.exists(path):
                continue
            mtime = os.path.getmtime(path)
            if path in self._mtimes and mtime > self._mtimes[path]:
                changed.append(path)
                if self.callback:
                    self.callback(path)
            self._mtimes[path] = mtime
        return changed


class PolicyDiff:
    """Compares two policy versions and reports changes."""

    @staticmethod
    def diff(old: dict, new: dict) -> dict:
        added = {k: v for k, v in new.items() if k not in old}
        removed = {k: v for k, v in old.items() if k not in new}
        changed = {k: {"old": old[k], "new": new[k]} for k in old if k in new and old[k] != new[k]}
        return {"added": added, "removed": removed, "changed": changed}


class NetworkEgressMonitor:
    """Monitors and controls outbound network connections."""

    def __init__(self) -> None:
        self.allowed_domains: list[str] = []
        self.blocked_domains: list[str] = []
        self._log: list[dict] = []

    def check(self, url: str) -> bool:
        from urllib.parse import urlparse
        domain = urlparse(url).netloc
        if self.blocked_domains and domain in self.blocked_domains:
            self._log.append({"url": url, "action": "blocked", "timestamp": time.time()})
            return False
        if self.allowed_domains and domain not in self.allowed_domains:
            self._log.append({"url": url, "action": "blocked_not_allowed", "timestamp": time.time()})
            return False
        self._log.append({"url": url, "action": "allowed", "timestamp": time.time()})
        return True

    def get_log(self) -> list[dict]:
        return list(self._log)
