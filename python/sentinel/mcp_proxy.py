"""Eresus Sentinel — Live MCP Intercepting Proxy.

Real-time security proxy that sits between MCP client and server,
inspecting every JSON-RPC message through the full Sentinel analysis
pipeline before forwarding.

Architecture:
    Client ←→ [SentinelProxy] ←→ MCP Server
                   ↕
         behavioral_analyzer
         static_analysis
         opa_engine
         policy engine
         telemetry pipeline

Features:
  - stdio / SSE / streamable-HTTP transport interception
  - Per-message behavioral analysis + taint tracking
  - OPA policy evaluation on every tool call
  - Real-time alert emission (webhook/Slack/PagerDuty)
  - Session-aware rate limiting + anomaly detection
  - Transparent passthrough mode (audit-only, no blocking)
  - Request/response modification (sanitization)
  - Configurable block/allow/audit actions
  - Circuit breaker for backend failures
  - Prometheus metrics export
"""

from __future__ import annotations

import asyncio
import json
import logging
import os
import threading
import time
import uuid
from collections import deque
from dataclasses import dataclass, field
from enum import Enum, auto
from typing import Any, Callable, Optional

logger = logging.getLogger(__name__)


async def _strip_server_header(_: Any, response: Any) -> None:
    """Avoid leaking the Python/aiohttp version from the proxy surface."""
    response.headers.pop("Server", None)


def _jsonrpc_error(message_id: Any, code: int, message: str) -> bytes:
    return json.dumps({
        "jsonrpc": "2.0",
        "id": message_id,
        "error": {"code": code, "message": message},
    }).encode()


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# DATA TYPES
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class ProxyAction(Enum):
    ALLOW = auto()
    BLOCK = auto()
    AUDIT = auto()
    MODIFY = auto()
    RATE_LIMIT = auto()


class ProxyMode(Enum):
    ENFORCE = "enforce"       # Block violations
    AUDIT = "audit"           # Log only, never block
    PASSTHROUGH = "passthrough"  # No inspection at all


class TransportType(Enum):
    STDIO = "stdio"
    SSE = "sse"
    HTTP = "http"


@dataclass
class ProxyFinding:
    finding_id: str
    category: str
    severity: str
    description: str
    evidence: str = ""
    action_taken: str = ""
    timestamp: float = 0.0
    session_id: str = ""
    message_id: str = ""
    cwe: str = ""


@dataclass
class InspectionResult:
    action: ProxyAction
    findings: list[ProxyFinding] = field(default_factory=list)
    risk_score: float = 0.0
    latency_ms: float = 0.0
    modified_message: Optional[dict] = None
    blocked_reason: str = ""


@dataclass
class SessionState:
    session_id: str
    created_at: float = 0.0
    request_count: int = 0
    tool_call_count: int = 0
    blocked_count: int = 0
    total_findings: int = 0
    last_activity: float = 0.0
    tools_called: deque = field(default_factory=lambda: deque(maxlen=500))
    anomaly_score: float = 0.0
    rate_tokens: float = 0.0
    rate_last_refill: float = 0.0


@dataclass
class ProxyConfig:
    mode: ProxyMode = ProxyMode.ENFORCE
    max_message_size: int = 10 * 1024 * 1024   # 10MB
    rate_limit_rps: float = 50.0
    rate_limit_burst: int = 100
    block_on_critical: bool = True
    block_on_high: bool = False
    block_threshold: float = 8.0   # risk score to block
    audit_threshold: float = 3.0   # risk score to audit
    enable_behavioral: bool = True
    enable_taint: bool = True
    enable_opa: bool = True
    enable_telemetry: bool = True
    allowed_tools: Optional[list[str]] = None   # None = allow all
    blocked_tools: list[str] = field(default_factory=list)
    max_param_depth: int = 10
    max_param_size: int = 100_000
    circuit_breaker_threshold: int = 5
    circuit_breaker_timeout: float = 30.0
    sanitize_responses: bool = True
    strip_sensitive_params: list[str] = field(default_factory=lambda: [
        "password", "passwd", "pass", "secret", "token", "api_key", "apikey",
        "access_token", "private_key", "credentials", "credential",
        "bearer", "auth", "authorization", "x-api-key", "x_api_key",
        "jwt", "id_token", "refresh_token", "client_secret", "client_id",
        "session", "session_token", "session_key", "cookie", "cookies",
        "sig", "signature", "nonce", "hmac", "signing_key",
        "aws_secret", "aws_access_key", "gcp_key", "azure_key",
    ])

    @classmethod
    def from_file(cls, path: str | os.PathLike[str]) -> "ProxyConfig":
        """Load proxy policy from a JSON/YAML config file."""
        from dataclasses import fields
        from pathlib import Path

        config_path = Path(path)
        text = config_path.read_text(encoding="utf-8")
        if config_path.suffix.lower() in {".yaml", ".yml"}:
            import yaml
            raw = yaml.safe_load(text) or {}
        else:
            raw = json.loads(text)
        if not isinstance(raw, dict):
            raise ValueError("proxy config must be a mapping")

        allowed = {field.name for field in fields(cls)}
        data = {key: value for key, value in raw.items() if key in allowed}
        if "mode" in data and not isinstance(data["mode"], ProxyMode):
            data["mode"] = ProxyMode(str(data["mode"]).lower())
        return cls(**data)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# RATE LIMITER (Token Bucket)
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class TokenBucketLimiter:
    """Per-session token bucket rate limiter."""

    def __init__(self, rate: float, burst: int):
        self._rate = rate
        self._burst = burst
        self._lock = threading.Lock()

    def check(self, session: SessionState) -> bool:
        with self._lock:
            now = time.monotonic()
            elapsed = now - session.rate_last_refill
            session.rate_tokens = min(
                self._burst,
                session.rate_tokens + elapsed * self._rate,
            )
            session.rate_last_refill = now

            if session.rate_tokens >= 1.0:
                session.rate_tokens -= 1.0
                return True
            return False


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# CIRCUIT BREAKER
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class CircuitBreaker:
    """Prevents cascade failures when backend MCP server is unhealthy."""

    def __init__(self, threshold: int = 5, timeout: float = 30.0):
        self._threshold = threshold
        self._timeout = timeout
        self._failure_count = 0
        self._last_failure: float = 0.0
        self._state = "closed"  # closed, open, half-open

    @property
    def is_open(self) -> bool:
        if self._state == "open":
            if time.monotonic() - self._last_failure > self._timeout:
                self._state = "half-open"
                return False
            return True
        return False

    def record_success(self) -> None:
        self._failure_count = 0
        self._state = "closed"

    def record_failure(self) -> None:
        self._failure_count += 1
        self._last_failure = time.monotonic()
        if self._failure_count >= self._threshold:
            self._state = "open"
            logger.warning("Circuit breaker OPEN after %d failures", self._failure_count)

    @property
    def state(self) -> str:
        return self._state


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# MESSAGE INSPECTOR
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class MessageInspector:
    """Runs the full Sentinel analysis pipeline on a JSON-RPC message."""

    def __init__(self, config: ProxyConfig):
        self._config = config
        self._behavioral = None
        self._static = None
        self._opa = None
        self._telemetry = None
        self._prompt_defense = None
        self._init_analyzers()

    def _init_analyzers(self) -> None:
        if self._config.enable_behavioral:
            try:
                from sentinel.agent.behavioral_analyzer import BehavioralAnalyzer
                self._behavioral = BehavioralAnalyzer()
            except Exception as e:
                logger.warning("BehavioralAnalyzer unavailable: %s", e)

        if self._config.enable_taint:
            try:
                from sentinel.agent.static_analysis import PromptDefenseAnalyzer, StaticAnalyzer
                self._static = StaticAnalyzer()
                self._prompt_defense = PromptDefenseAnalyzer()
            except Exception as e:
                logger.warning("StaticAnalyzer unavailable: %s", e)

        if self._config.enable_opa:
            try:
                from sentinel.opa_engine import OPAPolicyEngine
                self._opa = OPAPolicyEngine()
            except Exception as e:
                logger.warning("OPA engine unavailable: %s", e)

        if self._config.enable_telemetry:
            try:
                from sentinel.telemetry import TelemetryPipeline
                self._telemetry = TelemetryPipeline()
            except Exception as e:
                logger.warning("Telemetry unavailable: %s", e)

    def inspect_request(self, msg: dict, session: SessionState) -> InspectionResult:
        """Inspect an outgoing client→server request."""
        start = time.perf_counter()
        findings: list[ProxyFinding] = []
        risk = 0.0
        method = msg.get("method", "")
        params = msg.get("params", {})
        msg_id = str(msg.get("id", ""))

        # ── Size check
        raw_size = len(json.dumps(msg))
        if raw_size > self._config.max_message_size:
            findings.append(ProxyFinding(
                finding_id=f"proxy-{uuid.uuid4().hex[:8]}",
                category="oversized_message", severity="HIGH",
                description=f"Message exceeds size limit: {raw_size} > {self._config.max_message_size}",
                message_id=msg_id, session_id=session.session_id,
                timestamp=time.time(),
            ))
            risk += 5.0

        # ── Tool call inspection
        if method in ("tools/call", "tool/call"):
            tool_name = params.get("name", "")
            tool_args = params.get("arguments", {})

            # Blocked tool check
            if tool_name in self._config.blocked_tools:
                findings.append(ProxyFinding(
                    finding_id=f"proxy-{uuid.uuid4().hex[:8]}",
                    category="blocked_tool", severity="CRITICAL",
                    description=f"Tool '{tool_name}' is explicitly blocked",
                    evidence=tool_name, message_id=msg_id,
                    session_id=session.session_id, timestamp=time.time(),
                ))
                risk += 10.0

            # Allowlist check
            if self._config.allowed_tools is not None and tool_name not in self._config.allowed_tools:
                findings.append(ProxyFinding(
                    finding_id=f"proxy-{uuid.uuid4().hex[:8]}",
                    category="unauthorized_tool", severity="HIGH",
                    description=f"Tool '{tool_name}' not in allowlist",
                    evidence=tool_name, message_id=msg_id,
                    session_id=session.session_id, timestamp=time.time(),
                ))
                risk += 7.0

            # Deep parameter inspection
            param_findings = self._inspect_params(tool_name, tool_args, msg_id, session)
            findings.extend(param_findings)
            risk += sum(self._severity_score(f.severity) for f in param_findings)
            oversized_param = any(f.category == "oversized_param" for f in param_findings)

            try:
                from sentinel.tool_inspection import inspect_tool_arguments
                for tool_finding in inspect_tool_arguments(tool_name, tool_args):
                    severity = str(getattr(tool_finding.severity, "value", tool_finding.severity)).upper()
                    proxy_finding = ProxyFinding(
                        finding_id=f"proxy-{uuid.uuid4().hex[:8]}",
                        category="tool_inspection",
                        severity=severity,
                        description=tool_finding.title,
                        evidence=tool_finding.evidence,
                        message_id=msg_id,
                        session_id=session.session_id,
                        timestamp=time.time(),
                        cwe=(tool_finding.cwe_ids[0] if tool_finding.cwe_ids else ""),
                    )
                    findings.append(proxy_finding)
                    risk += self._severity_score(proxy_finding.severity)
            except Exception as e:
                logger.debug("Tool argument inspection error: %s", e)

            # Track tool call
            session.tool_call_count += 1
            session.tools_called.append(tool_name)

            # ── Behavioral analysis
            if self._behavioral and not oversized_param:
                try:
                    from sentinel.agent.behavioral_analyzer import ToolCallEvent
                    event = ToolCallEvent(
                        tool_name=tool_name,
                        parameters=tool_args,
                        timestamp=time.time(),
                        session_id=session.session_id,
                    )
                    beh_findings = self._behavioral.record_call(event)
                    for bf in beh_findings:
                        findings.append(ProxyFinding(
                            finding_id=f"proxy-{uuid.uuid4().hex[:8]}",
                            category=bf.category.name, severity=bf.severity,
                            description=bf.description,
                            evidence="; ".join(bf.evidence[:3]),
                            message_id=msg_id, session_id=session.session_id,
                            timestamp=time.time(),
                        ))
                        risk += self._severity_score(bf.severity)
                except Exception as e:
                    logger.debug("Behavioral analysis error: %s", e)

            # ── OPA policy check
            if self._opa and not oversized_param:
                try:
                    opa_input = {
                        "tool": tool_name,
                        "arguments": tool_args,
                        "session_id": session.session_id,
                        "request_count": session.request_count,
                        "tool_call_count": session.tool_call_count,
                    }
                    decision = self._opa.evaluate("tool_access", opa_input)
                    if decision and not decision.get("allow", True):
                        findings.append(ProxyFinding(
                            finding_id=f"proxy-{uuid.uuid4().hex[:8]}",
                            category="policy_violation", severity="CRITICAL",
                            description=f"OPA policy denied tool call: {decision.get('reason', 'policy violation')}",
                            evidence=json.dumps(opa_input)[:200],
                            message_id=msg_id, session_id=session.session_id,
                            timestamp=time.time(),
                        ))
                        risk += 10.0
                except Exception as e:
                    logger.debug("OPA evaluation error: %s", e)

        # ── Prompt/completion inspection (for sampling methods)
        if method in ("sampling/createMessage", "completion/complete"):
            content = self._extract_text_content(params)
            if content:
                prompt_findings = self._inspect_prompt_content(content, msg_id, session)
                findings.extend(prompt_findings)
                risk += sum(self._severity_score(f.severity) for f in prompt_findings)

        # ── Resource access inspection
        if method.startswith("resources/"):
            resource_uri = params.get("uri", "")
            res_findings = self._inspect_resource_access(resource_uri, msg_id, session)
            findings.extend(res_findings)
            risk += sum(self._severity_score(f.severity) for f in res_findings)

        # ── Anomaly scoring
        session.request_count += 1
        session.last_activity = time.time()
        session.total_findings += len(findings)

        # Rapid-fire anomaly
        if session.request_count > 100 and session.tool_call_count / max(session.request_count, 1) > 0.8:
            session.anomaly_score += 0.5
            if session.anomaly_score > 5.0:
                findings.append(ProxyFinding(
                    finding_id=f"proxy-{uuid.uuid4().hex[:8]}",
                    category="anomaly_detected", severity="HIGH",
                    description=f"Session anomaly score: {session.anomaly_score:.1f}",
                    message_id=msg_id, session_id=session.session_id,
                    timestamp=time.time(),
                ))
                risk += 5.0

        # ── Build result
        elapsed_ms = (time.perf_counter() - start) * 1000
        action = self._decide_action(risk, findings)

        result = InspectionResult(
            action=action,
            findings=findings,
            risk_score=risk,
            latency_ms=elapsed_ms,
            blocked_reason=findings[0].description if action == ProxyAction.BLOCK and findings else "",
        )

        # ── Telemetry
        if self._telemetry and findings:
            try:
                self._telemetry.emit_findings(
                    source="mcp_proxy",
                    findings=[{
                        "category": f.category,
                        "severity": f.severity,
                        "description": f.description,
                    } for f in findings],
                    metadata={"session_id": session.session_id, "risk": risk},
                )
            except Exception:
                pass

        # ── Structured audit event
        if action in (ProxyAction.BLOCK, ProxyAction.AUDIT) and findings:
            self._emit_gateway_event(
                event_type="mcp.proxy.request",
                action=action.value,
                session=session,
                method=method,
                msg_id=msg_id,
                risk=risk,
                findings=findings,
            )

        return result

    def _emit_gateway_event(
        self,
        *,
        event_type: str,
        action: str,
        session: SessionState,
        method: str,
        msg_id: str,
        risk: float,
        findings: list[ProxyFinding],
    ) -> None:
        """Emit a structured gateway-event-envelope audit record."""
        import uuid
        from datetime import datetime, timezone

        try:
            from sentinel.sink_registry import SinkRegistry
            payload = {
                "action": action,
                "method": method,
                "msg_id": msg_id,
                "session_id": session.session_id,
                "risk_score": round(risk, 3),
                "finding_count": len(findings),
                "findings": [
                    {
                        "category": f.category,
                        "severity": f.severity,
                        "description": f.description[:120],
                    }
                    for f in findings[:10]
                ],
            }
            envelope = {
                "envelope_id": str(uuid.uuid4()),
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "event_type": event_type,
                "version": "1.0",
                "source": "sentinel.mcp_proxy",
                "correlation_id": session.session_id,
                "payload": payload,
                "routing": {
                    "destination": "audit",
                    "priority": "high" if action == "block" else "normal",
                },
            }
            SinkRegistry().emit(envelope)
            try:
                from sentinel.audit_store import AuditStore
                AuditStore().record(
                    event_type=event_type,
                    target=method,
                    verdict=action,
                    session_id=session.session_id,
                    payload=payload,
                )
            except Exception as audit_exc:
                logger.debug("Failed to persist gateway audit event: %s", audit_exc)
        except Exception as exc:
            logger.debug("Failed to emit gateway event: %s", exc)

    def inspect_response(self, msg: dict, session: SessionState) -> InspectionResult:
        """Inspect an incoming server→client response."""
        start = time.perf_counter()
        findings: list[ProxyFinding] = []
        risk = 0.0
        msg_id = str(msg.get("id", ""))

        result_data = msg.get("result", {})
        error_data = msg.get("error", {})

        # ── Check for error information leakage
        if error_data:
            error_msg = str(error_data.get("message", ""))
            leak_patterns = [
                "traceback", "stack trace", "/home/", "/root/", "/etc/",
                "password", "secret", "token", "api_key",
                "connection string", "database url",
            ]
            for lp in leak_patterns:
                if lp.lower() in error_msg.lower():
                    findings.append(ProxyFinding(
                        finding_id=f"proxy-{uuid.uuid4().hex[:8]}",
                        category="information_leak", severity="HIGH",
                        description=f"Error response may leak sensitive info: '{lp}'",
                        evidence=error_msg[:200], message_id=msg_id,
                        session_id=session.session_id, timestamp=time.time(),
                    ))
                    risk += 5.0

        # ── Check response content for sensitive data
        if isinstance(result_data, dict):
            content = result_data.get("content", [])
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        text = item.get("text", "")
                        text_findings = self._inspect_response_text(text, msg_id, session)
                        findings.extend(text_findings)
                        risk += sum(self._severity_score(f.severity) for f in text_findings)

        # ── Sanitize if enabled
        modified = None
        if self._config.sanitize_responses and findings:
            modified = self._sanitize_response(msg, findings)

        elapsed_ms = (time.perf_counter() - start) * 1000
        action = self._decide_action(risk, findings)

        # ── Structured audit event for response blocks
        if action in (ProxyAction.BLOCK, ProxyAction.AUDIT) and findings:
            self._emit_gateway_event(
                event_type="mcp.proxy.response",
                action=action.value,
                session=session,
                method="response",
                msg_id=msg_id,
                risk=risk,
                findings=findings,
            )

        return InspectionResult(
            action=action, findings=findings,
            risk_score=risk, latency_ms=elapsed_ms,
            modified_message=modified,
        )

    def _inspect_params(self, tool: str, args: dict, msg_id: str, session: SessionState) -> list[ProxyFinding]:
        """Deep parameter inspection for injection, traversal, etc."""
        findings: list[ProxyFinding] = []

        import re
        injection_patterns = [
            (r"(?:;|\||\&\&|`|\$\()\s*(?:rm|cat|curl|wget|nc|bash|sh|python)", "command_injection", "CRITICAL", "CWE-78"),
            (r"\.\./|\.\.\\", "path_traversal", "HIGH", "CWE-22"),
            (r"(?i)(?:SELECT|INSERT|UPDATE|DELETE|DROP|UNION)\s+", "sql_injection", "CRITICAL", "CWE-89"),
            (r"(?i)<script|javascript:|on\w+\s*=", "xss_injection", "HIGH", "CWE-79"),
            (r"\$\{.*?\}|\{\{.*?\}\}", "template_injection", "HIGH", "CWE-1336"),
            (r"(?i)(?:file|gopher|dict|ftp|ldap|tftp)://", "ssrf_scheme", "CRITICAL", "CWE-918"),
            (r"(?i)https?://(?:127(?:\.\d{1,3}){3}|10(?:\.\d{1,3}){3}|172\.(?:1[6-9]|2\d|3[01])(?:\.\d{1,3}){2}|192\.168(?:\.\d{1,3}){2}|localhost|\[?::1\]?)(?::\d+)?(?:/|$)", "ssrf_internal", "CRITICAL", "CWE-918"),
            (r"(?i)169\.254\.169\.254|metadata\.google|metadata\.azure|0xa9fea9fe|2852039166", "ssrf_metadata", "CRITICAL", "CWE-918"),
            (r"\\x[0-9a-fA-F]{2}|\\u[0-9a-fA-F]{4}|%(?:2[ef]|0[0-9a-f])", "encoding_evasion", "MEDIUM", "CWE-116"),
            (r"(?i)__proto__|constructor\.prototype|Object\.assign", "prototype_pollution", "HIGH", "CWE-1321"),
            (r"(?i)(?:pickle|marshal|shelve|yaml\.(?:unsafe_)?load)\s*\(", "deserialization", "CRITICAL", "CWE-502"),
        ]

        def _scan_value(value: Any, path: str, depth: int = 0) -> None:
            if depth > self._config.max_param_depth:
                findings.append(ProxyFinding(
                    finding_id=f"proxy-{uuid.uuid4().hex[:8]}",
                    category="excessive_nesting", severity="MEDIUM",
                    description=f"Parameter nesting exceeds {self._config.max_param_depth} at {path}",
                    message_id=msg_id, session_id=session.session_id,
                    timestamp=time.time(),
                ))
                return

            if isinstance(value, str):
                if len(value) > self._config.max_param_size:
                    factor = len(value) / max(self._config.max_param_size, 1)
                    severity = "CRITICAL" if factor >= 4 else "HIGH"
                    findings.append(ProxyFinding(
                        finding_id=f"proxy-{uuid.uuid4().hex[:8]}",
                        category="oversized_param", severity=severity,
                        description=f"Parameter '{path}' exceeds size limit: {len(value)}",
                        message_id=msg_id, session_id=session.session_id,
                        timestamp=time.time(),
                    ))
                    # Oversized inputs should be handled as size violations first
                    # instead of paying regex/prompt-analysis cost on attacker-sized
                    # payloads that we already know should not proceed.
                    return

                for pat, cat, sev, cwe in injection_patterns:
                    if re.search(pat, value, re.IGNORECASE):
                        findings.append(ProxyFinding(
                            finding_id=f"proxy-{uuid.uuid4().hex[:8]}",
                            category=cat, severity=sev,
                            description=f"{cat} detected in {tool}.{path}",
                            evidence=value[:200], message_id=msg_id,
                            session_id=session.session_id,
                            timestamp=time.time(), cwe=cwe,
                        ))

                findings.extend(self._inspect_prompt_content(value, msg_id, session))

                # Sensitive param stripping
                param_name = path.split(".")[-1].lower()
                if param_name in self._config.strip_sensitive_params:
                    findings.append(ProxyFinding(
                        finding_id=f"proxy-{uuid.uuid4().hex[:8]}",
                        category="sensitive_param", severity="HIGH",
                        description=f"Sensitive parameter '{path}' in tool call",
                        message_id=msg_id, session_id=session.session_id,
                        timestamp=time.time(), cwe="CWE-200",
                    ))

            elif isinstance(value, dict):
                for k, v in value.items():
                    _scan_value(v, f"{path}.{k}", depth + 1)
            elif isinstance(value, list):
                for i, v in enumerate(value):
                    _scan_value(v, f"{path}[{i}]", depth + 1)

        for key, val in args.items():
            _scan_value(val, key)

        return findings

    def _inspect_prompt_content(self, text: str, msg_id: str, session: SessionState) -> list[ProxyFinding]:
        """Inspect prompt/completion text for prompt injection."""
        findings: list[ProxyFinding] = []
        if not self._prompt_defense:
            return findings
        try:
            pf = self._prompt_defense.detect_indirect_injection(text)
            for p in pf:
                findings.append(ProxyFinding(
                    finding_id=f"proxy-{uuid.uuid4().hex[:8]}",
                    category=f"prompt_{p.pattern_type}", severity=p.severity,
                    description=p.description,
                    evidence=p.match[:200], message_id=msg_id,
                    session_id=session.session_id, timestamp=time.time(),
                ))
        except Exception as e:
            logger.debug("Prompt inspection error: %s", e)
        return findings

    def _inspect_resource_access(self, uri: str, msg_id: str, session: SessionState) -> list[ProxyFinding]:
        """Inspect resource URI access."""
        findings: list[ProxyFinding] = []
        import re

        dangerous_patterns = [
            (r"\.\.(/|\\)", "path_traversal", "CRITICAL", "CWE-22"),
            (r"^file:///etc/", "sensitive_file", "CRITICAL", "CWE-22"),
            (r"^file:///root/", "sensitive_file", "CRITICAL", "CWE-22"),
            (r"^file://.*\.ssh/", "ssh_key_access", "CRITICAL", "CWE-200"),
            (r"^file://.*\.env$", "env_file_access", "HIGH", "CWE-200"),
            (r"^file://.*\.git/", "git_internals", "HIGH", "CWE-200"),
            (r"^(?:ftp|gopher|dict|ldap)://", "dangerous_scheme", "CRITICAL", "CWE-918"),
        ]

        for pat, cat, sev, cwe in dangerous_patterns:
            if re.search(pat, uri, re.IGNORECASE):
                findings.append(ProxyFinding(
                    finding_id=f"proxy-{uuid.uuid4().hex[:8]}",
                    category=cat, severity=sev,
                    description=f"Dangerous resource access: {cat}",
                    evidence=uri[:200], message_id=msg_id,
                    session_id=session.session_id,
                    timestamp=time.time(), cwe=cwe,
                ))
        return findings

    def _inspect_response_text(self, text: str, msg_id: str, session: SessionState) -> list[ProxyFinding]:
        """Check response text for sensitive data leakage."""
        findings: list[ProxyFinding] = []
        import re

        leak_patterns = [
            (r"(?:AKIA|ASIA)[A-Z0-9]{16}", "aws_key_leak", "CRITICAL"),
            (r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----", "private_key_leak", "CRITICAL"),
            (r"ghp_[A-Za-z0-9]{36}", "github_token_leak", "CRITICAL"),
            (r"sk-[A-Za-z0-9]{20,}", "openai_key_leak", "CRITICAL"),
            (r"xox[bpsar]-[A-Za-z0-9-]+", "slack_token_leak", "CRITICAL"),
            (r"\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,}\b", "email_leak", "MEDIUM"),
            (r"\b(?:\d{1,3}\.){3}\d{1,3}\b", "ip_address_leak", "LOW"),
            (r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "jwt_leak", "HIGH"),
            (r"(?:password|passwd|pwd)\s*[:=]\s*\S+", "password_leak", "CRITICAL"),
        ]

        for pat, cat, sev in leak_patterns:
            if re.search(pat, text):
                findings.append(ProxyFinding(
                    finding_id=f"proxy-{uuid.uuid4().hex[:8]}",
                    category=cat, severity=sev,
                    description=f"Potential data leak in response: {cat}",
                    message_id=msg_id, session_id=session.session_id,
                    timestamp=time.time(),
                ))

        return findings

    def _sanitize_response(self, msg: dict, findings: list[ProxyFinding]) -> dict:
        """Create a sanitized copy of the response."""
        import copy
        import re
        sanitized = copy.deepcopy(msg)

        critical = [f for f in findings if f.severity == "CRITICAL"]
        if not critical:
            return sanitized

        # Redact sensitive data from response content
        result_data = sanitized.get("result", {})
        if isinstance(result_data, dict):
            content = result_data.get("content", [])
            if isinstance(content, list):
                for item in content:
                    if isinstance(item, dict) and item.get("type") == "text":
                        text = item.get("text", "")
                        text = re.sub(r"(?:AKIA|ASIA)[A-Z0-9]{16}", "[REDACTED_AWS_KEY]", text)
                        text = re.sub(r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----[\s\S]*?-----END (?:RSA |EC |DSA )?PRIVATE KEY-----", "[REDACTED_PRIVATE_KEY]", text)
                        text = re.sub(r"ghp_[A-Za-z0-9]{36}", "[REDACTED_GITHUB_TOKEN]", text)
                        text = re.sub(r"sk-[A-Za-z0-9]{20,}", "[REDACTED_OPENAI_KEY]", text)
                        text = re.sub(r"xox[bpsar]-[A-Za-z0-9-]+", "[REDACTED_SLACK_TOKEN]", text)
                        text = re.sub(r"eyJ[A-Za-z0-9_-]+\.eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+", "[REDACTED_JWT]", text)
                        item["text"] = text

        return sanitized

    def _extract_text_content(self, params: dict) -> str:
        """Extract text from MCP sampling/completion messages."""
        messages = params.get("messages", [])
        parts = []
        for m in messages:
            content = m.get("content", {})
            if isinstance(content, str):
                parts.append(content)
            elif isinstance(content, dict) and content.get("type") == "text":
                parts.append(content.get("text", ""))
            elif isinstance(content, list):
                for c in content:
                    if isinstance(c, dict) and c.get("type") == "text":
                        parts.append(c.get("text", ""))
        return "\n".join(parts)

    def _decide_action(self, risk: float, findings: list[ProxyFinding]) -> ProxyAction:
        """Determine proxy action based on risk and config."""
        if self._config.mode == ProxyMode.PASSTHROUGH:
            return ProxyAction.ALLOW
        if self._config.mode == ProxyMode.AUDIT:
            return ProxyAction.AUDIT if findings else ProxyAction.ALLOW

        # Enforce mode
        if self._config.block_on_critical and any(f.severity == "CRITICAL" for f in findings):
            return ProxyAction.BLOCK
        if self._config.block_on_high and any(f.severity == "HIGH" for f in findings):
            return ProxyAction.BLOCK
        if risk >= self._config.block_threshold:
            return ProxyAction.BLOCK
        if risk >= self._config.audit_threshold:
            return ProxyAction.AUDIT
        return ProxyAction.ALLOW

    @staticmethod
    def _severity_score(sev: str) -> float:
        return {"CRITICAL": 10.0, "HIGH": 5.0, "MEDIUM": 2.0, "LOW": 0.5, "INFO": 0.1}.get(sev, 0.0)


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# MCP PROXY ENGINE
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

class MCPProxy:
    """
    Live MCP intercepting proxy.

    Sits between client and server, inspecting every message.
    Supports stdio, SSE, and HTTP transports.

    Usage:
        proxy = MCPProxy(ProxyConfig(mode=ProxyMode.ENFORCE))

        # stdio mode
        await proxy.run_stdio(
            server_cmd=["python", "-m", "my_mcp_server"],
            listen_port=None,  # stdio passthrough
        )

        # HTTP mode
        await proxy.run_http(
            upstream_url="http://localhost:3000",
            listen_host="0.0.0.0",
            listen_port=8080,
        )
    """

    def __init__(self, config: ProxyConfig | None = None):
        self._config = config or ProxyConfig()
        self._inspector = MessageInspector(self._config)
        self._limiter = TokenBucketLimiter(
            self._config.rate_limit_rps,
            self._config.rate_limit_burst,
        )
        self._breaker = CircuitBreaker(
            self._config.circuit_breaker_threshold,
            self._config.circuit_breaker_timeout,
        )
        self._sessions: dict[str, SessionState] = {}
        self._stats = {
            "total_requests": 0,
            "total_responses": 0,
            "total_blocked": 0,
            "total_findings": 0,
            "total_latency_ms": 0.0,
        }
        self._hooks_pre: list[Callable] = []
        self._hooks_post: list[Callable] = []

    def register_hook(self, phase: str, callback: Callable) -> None:
        """Register a pre/post inspection hook."""
        if phase == "pre":
            self._hooks_pre.append(callback)
        elif phase == "post":
            self._hooks_post.append(callback)

    def get_session(self, session_id: str | None = None) -> SessionState:
        """Get or create session state."""
        sid = session_id or "default"
        if sid not in self._sessions:
            now = time.time()
            self._sessions[sid] = SessionState(
                session_id=sid, created_at=now,
                rate_last_refill=time.monotonic(),
                rate_tokens=float(self._config.rate_limit_burst),
            )
        return self._sessions[sid]

    @staticmethod
    def _stdio_client_response(
        forwarded: bytes | None,
        result: InspectionResult,
    ) -> tuple[bytes | None, bytes | None]:
        """Split a stdio inspection result into upstream and client payloads."""
        if result.action == ProxyAction.BLOCK:
            if forwarded is not None:
                return None, forwarded
            return None, _jsonrpc_error(None, -32600, result.blocked_reason or "Blocked by Sentinel")
        if result.action == ProxyAction.RATE_LIMIT:
            return None, _jsonrpc_error(None, -32600, "Rate limited")
        return forwarded, None

    async def handle_client_message(self, raw: bytes, session_id: str | None = None) -> tuple[bytes | None, InspectionResult]:
        """
        Process a client→server message.

        Returns:
            (forwarded_bytes, inspection_result)
            forwarded_bytes is None if blocked.
        """
        session = self.get_session(session_id)

        # Rate limit
        if not self._limiter.check(session):
            result = InspectionResult(
                action=ProxyAction.RATE_LIMIT,
                blocked_reason="Rate limit exceeded",
                risk_score=0.0,
            )
            self._stats["total_blocked"] += 1
            return None, result

        # Circuit breaker
        if self._breaker.is_open:
            result = InspectionResult(
                action=ProxyAction.BLOCK,
                blocked_reason="Circuit breaker open — backend unhealthy",
            )
            return None, result

        # Parse
        try:
            msg = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            # Malformed — block
            result = InspectionResult(
                action=ProxyAction.BLOCK,
                blocked_reason="Malformed JSON-RPC message",
                risk_score=10.0,
                findings=[ProxyFinding(
                    finding_id=f"proxy-{uuid.uuid4().hex[:8]}",
                    category="malformed_message", severity="HIGH",
                    description="Cannot parse JSON-RPC message",
                    session_id=session.session_id, timestamp=time.time(),
                )],
            )
            return _jsonrpc_error(None, -32700, "Malformed JSON-RPC message"), result

        # Pre-hooks
        for hook in self._hooks_pre:
            try:
                hook(msg, session)
            except Exception:
                pass

        # Inspect
        result = self._inspector.inspect_request(msg, session)
        self._stats["total_requests"] += 1
        self._stats["total_findings"] += len(result.findings)
        self._stats["total_latency_ms"] += result.latency_ms

        if result.action == ProxyAction.BLOCK:
            self._stats["total_blocked"] += 1
            session.blocked_count += 1

            # Return JSON-RPC error
            return _jsonrpc_error(
                msg.get("id"),
                -32600,
                f"Blocked by Sentinel: {result.blocked_reason}",
            ), result

        # Post-hooks
        for hook in self._hooks_post:
            try:
                hook(msg, result, session)
            except Exception:
                pass

        # Forward (possibly modified)
        forward = result.modified_message if result.modified_message else msg
        return json.dumps(forward).encode(), result

    async def handle_server_message(self, raw: bytes, session_id: str | None = None) -> tuple[bytes, InspectionResult]:
        """Process a server→client response."""
        session = self.get_session(session_id)

        try:
            msg = json.loads(raw)
        except (json.JSONDecodeError, UnicodeDecodeError):
            return raw, InspectionResult(action=ProxyAction.ALLOW)

        result = self._inspector.inspect_response(msg, session)
        self._stats["total_responses"] += 1

        if result.modified_message:
            return json.dumps(result.modified_message).encode(), result

        if result.action == ProxyAction.BLOCK:
            error_response = {
                "jsonrpc": "2.0",
                "id": msg.get("id"),
                "error": {
                    "code": -32600,
                    "message": "Response blocked by Sentinel security policy",
                },
            }
            return json.dumps(error_response).encode(), result

        return raw, result

    async def run_stdio(self, server_cmd: list[str], env: dict | None = None) -> None:
        """
        Run proxy in stdio mode.

        Spawns the MCP server subprocess, intercepts all stdin/stdout
        communication between client and server.
        """
        logger.info("Starting MCP proxy in stdio mode: %s", " ".join(server_cmd))

        # SECURITY: strip dangerous environment variables before spawning subprocess
        _BLOCKED_ENV = {
            "LD_PRELOAD", "LD_LIBRARY_PATH", "DYLD_INSERT_LIBRARIES",
            "DYLD_LIBRARY_PATH", "PYTHONPATH", "NODE_OPTIONS",
            "NODE_PATH", "PYTHONSTARTUP", "PYTHONDONTWRITEBYTECODE",
        }
        safe_env = {k: v for k, v in os.environ.items() if k not in _BLOCKED_ENV}
        user_env = {k: v for k, v in (env or {}).items() if k not in _BLOCKED_ENV}

        proc = await asyncio.create_subprocess_exec(
            *server_cmd,
            stdin=asyncio.subprocess.PIPE,
            stdout=asyncio.subprocess.PIPE,
            stderr=asyncio.subprocess.PIPE,
            env={**safe_env, **user_env},
        )

        session_id = f"stdio-{uuid.uuid4().hex[:8]}"

        async def _client_to_server():
            """Read from our stdin, inspect, forward to server."""
            reader = asyncio.StreamReader()
            protocol = asyncio.StreamReaderProtocol(reader)
            await asyncio.get_event_loop().connect_read_pipe(lambda: protocol, os.fdopen(0, 'rb'))

            while True:
                line = await reader.readline()
                if not line:
                    break

                forwarded, result = await self.handle_client_message(line.strip(), session_id)
                to_server, to_client = self._stdio_client_response(forwarded, result)

                if to_client:
                    import sys
                    sys.stdout.buffer.write(to_client + b"\n")
                    sys.stdout.buffer.flush()

                if to_server and proc.stdin:
                    proc.stdin.write(to_server + b"\n")
                    await proc.stdin.drain()

                    if result.action == ProxyAction.BLOCK:
                        logger.warning("[BLOCKED] %s", result.blocked_reason)
                    elif result.action == ProxyAction.RATE_LIMIT:
                        logger.warning("[RATE LIMITED] %s", result.blocked_reason)
                    elif result.findings:
                        logger.info("[AUDIT] %d findings, risk=%.1f",
                                    len(result.findings), result.risk_score)
                elif result.action == ProxyAction.BLOCK:
                    logger.warning("[BLOCKED] %s", result.blocked_reason)
                elif result.action == ProxyAction.RATE_LIMIT:
                    logger.warning("[RATE LIMITED] %s", result.blocked_reason)

        async def _server_to_client():
            """Read from server stdout, inspect, forward to our stdout."""
            while True:
                line = await proc.stdout.readline()
                if not line:
                    break

                forwarded, result = await self.handle_server_message(line.strip(), session_id)

                import sys
                sys.stdout.buffer.write(forwarded + b"\n")
                sys.stdout.buffer.flush()

                if result.findings:
                    logger.info("[RESPONSE AUDIT] %d findings", len(result.findings))

                self._breaker.record_success()

        try:
            await asyncio.gather(
                _client_to_server(),
                _server_to_client(),
            )
        except Exception as e:
            logger.error("Proxy error: %s", e)
            self._breaker.record_failure()
        finally:
            if proc.returncode is None:
                proc.terminate()
                await proc.wait()

    async def run_http(
        self,
        upstream_url: str,
        listen_host: str = "127.0.0.1",
        listen_port: int = 8080,
    ) -> None:
        """
        Run proxy in HTTP mode.

        Listens for HTTP POST requests, inspects, forwards to upstream
        MCP server, inspects response, and returns to client.
        """
        try:
            from aiohttp import ClientSession, web
        except ImportError:
            logger.error("aiohttp required for HTTP proxy mode: pip install aiohttp")
            return

        async def _handle_request(request: web.Request) -> web.Response:
            body = await request.read()
            session_id = request.headers.get("X-Session-ID", f"http-{uuid.uuid4().hex[:8]}")

            # Inspect client request
            forwarded, req_result = await self.handle_client_message(body, session_id)

            if req_result.action == ProxyAction.BLOCK:
                return web.json_response(
                    json.loads(forwarded) if forwarded else {"error": "blocked"},
                    status=403,
                )

            if req_result.action == ProxyAction.RATE_LIMIT:
                return web.json_response(
                    {"error": {"code": -32600, "message": "Rate limited"}},
                    status=429,
                    headers={"Retry-After": "1"},
                )

            # Forward to upstream
            async with ClientSession() as cs:
                try:
                    async with cs.post(upstream_url, data=forwarded, headers={
                        "Content-Type": "application/json",
                    }) as resp:
                        resp_body = await resp.read()
                        self._breaker.record_success()
                except Exception:
                    self._breaker.record_failure()
                    return web.json_response(
                        {"error": {"code": -32603, "message": "Upstream error"}},
                        status=502,
                    )

            # Inspect server response
            final_body, resp_result = await self.handle_server_message(resp_body, session_id)

            return web.Response(
                body=final_body,
                content_type="application/json",
                headers={
                    "X-Sentinel-Risk": str(max(req_result.risk_score, resp_result.risk_score)),
                    "X-Sentinel-Findings": str(len(req_result.findings) + len(resp_result.findings)),
                },
            )

        app = web.Application()
        app.on_response_prepare.append(_strip_server_header)
        app.router.add_post("/", _handle_request)
        app.router.add_post("/mcp", _handle_request)
        app.router.add_post("/v1/mcp", _handle_request)

        # Health endpoint
        async def _health(_: web.Request) -> web.Response:
            return web.json_response({
                "status": "healthy",
                "mode": self._config.mode.value,
                "circuit_breaker": self._breaker.state,
                "stats": self._stats,
                "sessions": len(self._sessions),
            })
        app.router.add_get("/health", _health)

        runner = web.AppRunner(app)
        await runner.setup()
        site = web.TCPSite(runner, listen_host, listen_port)
        logger.info("MCP HTTP Proxy listening on %s:%d → %s", listen_host, listen_port, upstream_url)
        await site.start()

        # Keep running
        try:
            await asyncio.Event().wait()
        finally:
            await runner.cleanup()

    @property
    def stats(self) -> dict:
        return dict(self._stats)

    @property
    def sessions(self) -> dict[str, SessionState]:
        return dict(self._sessions)
