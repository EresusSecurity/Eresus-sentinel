# ruff: noqa: E501,TC003
"""Langchain & Google ADK middleware integrations."""

from __future__ import annotations

import logging
import os
import time
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


# ── Langchain Middleware ──

_VALID_MODES = {"monitor", "enforce", "off"}

@dataclass
class InspectionResult:
    allowed: bool = True
    score: float = 0.0
    rule: str = ""
    details: str = ""
    mode: str = "monitor"


class SentinelLangchainMiddleware:
    """Middleware for intercepting Langchain LLM calls.

    Supports two modes:
    - monitor: log and score but don't block
    - enforce: block requests/responses that fail guardrails
    """

    def __init__(self, mode: str = "monitor", rules: list[dict] | None = None):
        self.mode = _validate_mode(mode)
        self.rules = rules or []
        self._log: list[dict] = []

    def inspect_input(self, messages: list[dict]) -> InspectionResult:
        text = " ".join(m.get("content", "") for m in messages)
        return self._check(text, direction="input")

    def inspect_output(self, output: str) -> InspectionResult:
        return self._check(output, direction="output")

    def _check(self, text: str, direction: str) -> InspectionResult:
        text_lower = text.lower()
        for rule in self.rules:
            rule_type = rule.get("type", "ban_substring")
            value = rule.get("value", "")
            name = rule.get("name", "unnamed")

            if rule_type == "ban_substring" and value.lower() in text_lower:
                result = InspectionResult(allowed=self.mode != "enforce", score=1.0, rule=name, details=f"Banned substring '{value}' found", mode=self.mode)
                self._log.append({"direction": direction, "rule": name, "action": "blocked" if not result.allowed else "flagged", "timestamp": time.time()})
                return result
            elif rule_type == "regex":
                import re
                if re.search(value, text, re.IGNORECASE):
                    result = InspectionResult(allowed=self.mode != "enforce", score=0.8, rule=name, details=f"Regex match on '{value}'", mode=self.mode)
                    self._log.append({"direction": direction, "rule": name, "action": "blocked" if not result.allowed else "flagged", "timestamp": time.time()})
                    return result
            elif rule_type == "max_tokens":
                token_est = len(text.split())
                if token_est > int(value):
                    result = InspectionResult(allowed=self.mode != "enforce", score=0.5, rule=name, details=f"Token limit exceeded: {token_est} > {value}", mode=self.mode)
                    self._log.append({"direction": direction, "rule": name, "action": "blocked" if not result.allowed else "flagged", "timestamp": time.time()})
                    return result

        return InspectionResult(allowed=True, mode=self.mode)

    def get_log(self) -> list[dict]:
        return list(self._log)


class SentinelToolInspector:
    """Inspects Langchain tool calls for safety."""

    def __init__(self, allowed_tools: list[str] | None = None, blocked_tools: list[str] | None = None):
        self.allowed_tools = allowed_tools
        self.blocked_tools = blocked_tools or []

    def check_tool_call(self, tool_name: str, tool_input: dict) -> InspectionResult:
        if tool_name in self.blocked_tools:
            return InspectionResult(allowed=False, score=1.0, rule="blocked_tool", details=f"Tool '{tool_name}' is blocked")
        if self.allowed_tools and tool_name not in self.allowed_tools:
            return InspectionResult(allowed=False, score=0.8, rule="unlisted_tool", details=f"Tool '{tool_name}' not in allowed list")

        input_str = str(tool_input).lower()
        dangerous_patterns = ["rm -rf", "drop table", "delete from", "os.system", "subprocess", "eval("]
        for pat in dangerous_patterns:
            if pat in input_str:
                return InspectionResult(allowed=False, score=1.0, rule="dangerous_input", details=f"Dangerous pattern '{pat}' in tool input")

        return InspectionResult(allowed=True)


def _validate_mode(mode: str) -> str:
    normalized = mode.strip().lower()
    if normalized not in _VALID_MODES:
        raise ValueError(f"mode must be one of {sorted(_VALID_MODES)}, got {mode!r}")
    return normalized


def _mode_from_env(default: str = "monitor") -> str:
    mode = os.getenv("AI_DEFENSE_MODE") or os.getenv("SENTINEL_MIDDLEWARE_MODE") or default
    normalized = mode.strip().lower()
    return normalized if normalized in _VALID_MODES else default


def _messages_from_state(state: Any) -> list[dict[str, Any]]:
    if isinstance(state, dict) and isinstance(state.get("messages"), list):
        raw_messages = state["messages"]
    elif isinstance(state, list):
        raw_messages = state
    else:
        raw_messages = [{"role": "user", "content": str(state)}]

    messages: list[dict[str, Any]] = []
    for message in raw_messages:
        if isinstance(message, dict):
            messages.append(
                {
                    "role": message.get("role") or message.get("type") or "user",
                    "content": _flatten_content(message.get("content", "")),
                }
            )
        else:
            role = getattr(message, "role", None) or getattr(message, "type", None) or "user"
            content = getattr(message, "content", message)
            messages.append({"role": role, "content": _flatten_content(content)})
    return messages


def _flatten_content(content: Any) -> str:
    if isinstance(content, str):
        return content
    if isinstance(content, list):
        return " ".join(_flatten_content(item) for item in content)
    if isinstance(content, dict):
        if "text" in content:
            return _flatten_content(content["text"])
        if "content" in content:
            return _flatten_content(content["content"])
    return str(content)


def _tool_call_from_request(request: Any) -> tuple[str, dict[str, Any]]:
    if isinstance(request, dict):
        tool_call = request.get("tool_call", request)
    else:
        tool_call = getattr(request, "tool_call", request)
    if isinstance(tool_call, dict):
        name = str(tool_call.get("name") or tool_call.get("tool") or "unknown")
        args = tool_call.get("args") or tool_call.get("input") or {}
        return name, args if isinstance(args, dict) else {"value": args}
    return str(tool_call), {}


def _blocked_payload(reason: str, rule: str = "") -> dict[str, Any]:
    return {"blocked": True, "reason": reason, "rule": rule, "jump_to": "end"}


class ChatInspectionClient:
    """Reference-compatible chat inspection client for LangChain middleware tests."""

    def __init__(self, mode: str | None = None, rules: list[dict] | None = None):
        self.middleware = SentinelLangchainMiddleware(mode=mode or _mode_from_env(), rules=rules)

    def inspect_messages(self, messages: list[dict[str, Any]]) -> InspectionResult:
        if self.middleware.mode == "off":
            return InspectionResult(allowed=True, mode="off")
        return self.middleware.inspect_input(messages)

    def inspect_response(self, response: str) -> InspectionResult:
        if self.middleware.mode == "off":
            return InspectionResult(allowed=True, mode="off")
        return self.middleware.inspect_output(response)


class AIDefenseMiddleware:
    """Reference-compatible ChatInspectionClient middleware facade.

    This lightweight adapter intentionally avoids importing LangChain or Cisco
    SDK packages. It exposes the same hook names and mode behavior while
    delegating deterministic inspection to Sentinel's local middleware.
    """

    def __init__(
        self,
        api_key: str | None = None,
        region: str = "us-west-2",
        mode: str | None = None,
        fail_open: bool = True,
        timeout: int = 30,
        rules: list[dict] | None = None,
        user: str | None = None,
        src_app: str | None = None,
        on_violation: Callable[[InspectionResult, str], None] | None = None,
        **_: Any,
    ):
        self.api_key = api_key
        self.region = region
        self.mode = _validate_mode(mode or _mode_from_env("enforce"))
        self.fail_open = fail_open
        self.timeout = timeout
        self.user = user
        self.src_app = src_app
        self.on_violation = on_violation
        self.client = ChatInspectionClient(mode=self.mode, rules=rules)

    @classmethod
    def from_env(cls, **kwargs: Any) -> AIDefenseMiddleware:
        kwargs.setdefault("api_key", os.getenv("AI_DEFENSE_API_KEY"))
        kwargs.setdefault("region", os.getenv("AI_DEFENSE_REGION", "us-west-2"))
        kwargs.setdefault("mode", _mode_from_env("enforce"))
        return cls(**kwargs)

    def before_model(self, state: Any, runtime: Any = None) -> dict[str, Any] | None:
        if self.mode == "off":
            return None
        result = self.client.inspect_messages(_messages_from_state(state))
        return self._handle_result(result, "input")

    async def abefore_model(self, state: Any, runtime: Any = None) -> dict[str, Any] | None:
        return self.before_model(state, runtime)

    def after_model(self, state: Any, runtime: Any = None) -> dict[str, Any] | None:
        if self.mode == "off":
            return None
        messages = _messages_from_state(state)
        response = messages[-1]["content"] if messages else str(state)
        result = self.client.inspect_response(response)
        return self._handle_result(result, "output")

    async def aafter_model(self, state: Any, runtime: Any = None) -> dict[str, Any] | None:
        return self.after_model(state, runtime)

    def _handle_result(self, result: InspectionResult, direction: str) -> dict[str, Any] | None:
        if result.allowed and result.score <= 0:
            return None
        if self.on_violation:
            self.on_violation(result, direction)
        if self.mode == "enforce":
            return _blocked_payload(result.details, result.rule)
        return None


class MCPInspectionClient:
    """Reference-compatible MCP/tool inspection client."""

    def __init__(
        self,
        allowed_tools: list[str] | None = None,
        blocked_tools: list[str] | None = None,
        mode: str | None = None,
    ):
        self.mode = mode or _mode_from_env()
        self.inspector = SentinelToolInspector(
            allowed_tools=allowed_tools,
            blocked_tools=blocked_tools,
        )

    def inspect_tool_call(self, tool_name: str, tool_input: dict[str, Any]) -> InspectionResult:
        if self.mode == "off":
            return InspectionResult(allowed=True, mode="off")
        result = self.inspector.check_tool_call(tool_name, tool_input)
        if self.mode == "monitor" and not result.allowed:
            return InspectionResult(
                allowed=True,
                score=result.score,
                rule=result.rule,
                details=result.details,
                mode=self.mode,
            )
        result.mode = self.mode
        return result


class AIDefenseAgentsecMiddleware(SentinelLangchainMiddleware):
    """AgentSec-compatible alias with monitor/enforce/off mode semantics."""

    def __init__(self, mode: str | None = None, rules: list[dict] | None = None, **_: Any):
        super().__init__(mode=mode or _mode_from_env("enforce"), rules=rules)

    @classmethod
    def from_env(cls, **kwargs: Any) -> AIDefenseAgentsecMiddleware:
        kwargs.setdefault("mode", _mode_from_env("enforce"))
        return cls(**kwargs)

    def before_model(self, messages: list[dict[str, Any]] | dict[str, Any]) -> InspectionResult:
        if self.mode == "off":
            return InspectionResult(allowed=True, mode="off")
        return self.inspect_input(_messages_from_state(messages))

    async def abefore_model(self, messages: list[dict[str, Any]] | dict[str, Any]) -> InspectionResult:
        return self.before_model(messages)

    def after_model(self, response: str) -> InspectionResult:
        if self.mode == "off":
            return InspectionResult(allowed=True, mode="off")
        return self.inspect_output(_flatten_content(response))

    async def aafter_model(self, response: str) -> InspectionResult:
        return self.after_model(response)


class AIDefenseToolMiddleware:
    """Reference-compatible tool/MCP middleware facade."""

    def __init__(
        self,
        api_key: str | None = None,
        region: str = "us-west-2",
        mode: str | None = None,
        fail_open: bool = True,
        timeout: int = 30,
        allowed_tools: list[str] | None = None,
        blocked_tools: list[str] | None = None,
        inspect_requests: bool = True,
        inspect_responses: bool = True,
        on_violation: Callable[[InspectionResult, str, str], None] | None = None,
        **_: Any,
    ):
        self.api_key = api_key
        self.region = region
        self.mode = _validate_mode(mode or _mode_from_env("enforce"))
        self.fail_open = fail_open
        self.timeout = timeout
        self.inspect_requests = inspect_requests
        self.inspect_responses = inspect_responses
        self.on_violation = on_violation
        self.client = MCPInspectionClient(
            allowed_tools=allowed_tools,
            blocked_tools=blocked_tools,
            mode=self.mode,
        )

    @classmethod
    def from_env(cls, **kwargs: Any) -> AIDefenseToolMiddleware:
        kwargs.setdefault("api_key", os.getenv("AI_DEFENSE_API_KEY"))
        kwargs.setdefault("region", os.getenv("AI_DEFENSE_REGION", "us-west-2"))
        kwargs.setdefault("mode", _mode_from_env("enforce"))
        return cls(**kwargs)

    def wrap_tool_call(self, request: Any, handler: Callable[[Any], Any] | None = None) -> Any:
        if self.mode == "off":
            return handler(request) if handler else request
        tool_name, tool_input = _tool_call_from_request(request)
        if self.inspect_requests:
            result = self.client.inspect_tool_call(tool_name, tool_input)
            blocked = self._handle_result(result, tool_name, "request")
            if blocked is not None:
                return blocked
        tool_result = handler(request) if handler else request
        if self.inspect_responses:
            response_result = self.client.inspect_tool_call(
                tool_name,
                {"request": tool_input, "response": _flatten_content(tool_result)},
            )
            blocked = self._handle_result(response_result, tool_name, "response")
            if blocked is not None:
                return blocked
        return tool_result

    async def awrap_tool_call(self, request: Any, handler: Callable[[Any], Any] | None = None) -> Any:
        if handler is None:
            return self.wrap_tool_call(request)
        if self.mode == "off":
            result = handler(request)
            return await result if hasattr(result, "__await__") else result
        return self.wrap_tool_call(request, handler)

    def _handle_result(
        self,
        result: InspectionResult,
        tool_name: str,
        direction: str,
    ) -> dict[str, Any] | None:
        if result.allowed and result.score <= 0:
            return None
        if self.on_violation:
            self.on_violation(result, tool_name, direction)
        if self.mode == "enforce":
            return _blocked_payload(result.details, result.rule)
        return None


class AIDefenseToolInspectionMiddleware:
    """AgentSec-compatible tool middleware wrapper."""

    def __init__(
        self,
        allowed_tools: list[str] | None = None,
        blocked_tools: list[str] | None = None,
        mode: str | None = None,
    ):
        self.client = MCPInspectionClient(
            allowed_tools=allowed_tools,
            blocked_tools=blocked_tools,
            mode=mode,
        )

    def before_tool(self, tool_name: str, tool_input: dict[str, Any]) -> InspectionResult:
        return self.client.inspect_tool_call(tool_name, tool_input)

    def wrap_tool_call(self, request: Any, handler: Callable[[Any], Any] | None = None) -> Any:
        return AIDefenseToolMiddleware(
            allowed_tools=self.client.inspector.allowed_tools,
            blocked_tools=self.client.inspector.blocked_tools,
            mode=self.client.mode,
        ).wrap_tool_call(request, handler)


AIDefenseAgentsecToolMiddleware = AIDefenseToolInspectionMiddleware


# ── Google ADK Callbacks ──

class SentinelADKCallback:
    """Callback handler for Google Agent Development Kit."""

    def __init__(self, mode: str = "monitor", rules: list[dict] | None = None):
        self.middleware = SentinelLangchainMiddleware(mode=mode, rules=rules or [])

    def before_model_call(self, messages: list[dict], **kwargs: Any) -> dict:
        result = self.middleware.inspect_input(messages)
        if not result.allowed:
            return {"blocked": True, "reason": result.details, "rule": result.rule}
        return {"blocked": False}

    def after_model_call(self, response: str, **kwargs: Any) -> dict:
        result = self.middleware.inspect_output(response)
        if not result.allowed:
            return {"blocked": True, "reason": result.details, "rule": result.rule}
        return {"blocked": False}

    def before_tool_call(self, tool_name: str, tool_input: dict, **kwargs: Any) -> dict:
        inspector = SentinelToolInspector()
        result = inspector.check_tool_call(tool_name, tool_input)
        if not result.allowed:
            return {"blocked": True, "reason": result.details}
        return {"blocked": False}


# ── MCP Prompt & Resource Scanner ──

@dataclass
class MCPPromptScanResult:
    name: str = ""
    safe: bool = True
    issues: list[str] = field(default_factory=list)

@dataclass
class MCPResourceScanResult:
    uri: str = ""
    safe: bool = True
    issues: list[str] = field(default_factory=list)


class MCPPromptScanner:
    """Scans MCP server prompts for injection/safety issues."""

    DANGEROUS_PATTERNS = [
        "ignore previous", "system prompt", "override", "bypass",
        "admin mode", "unrestricted", "no restrictions", "disable safety",
    ]

    def scan_prompt(self, name: str, description: str, template: str = "") -> MCPPromptScanResult:
        result = MCPPromptScanResult(name=name)
        full_text = f"{description} {template}".lower()
        for pat in self.DANGEROUS_PATTERNS:
            if pat in full_text:
                result.safe = False
                result.issues.append(f"Dangerous pattern '{pat}' in prompt definition")
        return result

    def scan_resource(self, uri: str, description: str, content: str = "") -> MCPResourceScanResult:
        result = MCPResourceScanResult(uri=uri)
        full_text = f"{description} {content}".lower()
        for pat in self.DANGEROUS_PATTERNS:
            if pat in full_text:
                result.safe = False
                result.issues.append(f"Dangerous pattern '{pat}' in resource")
        if any(s in uri.lower() for s in ["file://", "../../", "/etc/", "/proc/"]):
            result.safe = False
            result.issues.append(f"Suspicious URI pattern in resource: {uri}")
        return result
