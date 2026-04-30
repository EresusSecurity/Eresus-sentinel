"""Google Agent Development Kit (ADK) plugin for Eresus Sentinel.

Provides before/after model and before/after tool callbacks that wrap any
ADK agent with Sentinel input/output guardrails. Operates in three modes:

* ``off``      — passthrough, no inspection.
* ``monitor``  — scans and logs, never blocks.
* ``enforce``  — blocks when scanners raise CRITICAL/HIGH severity.

The plugin is intentionally decoupled from ``google-adk`` itself — the
optional dependency is only imported when :meth:`apply_to` is called.
"""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any, Callable, Literal, Optional

from sentinel.firewall.base import ScanAction, ScanResult
from sentinel.middleware import SentinelMiddleware

logger = logging.getLogger(__name__)

Mode = Literal["off", "monitor", "enforce"]


@dataclass
class ADKCallbackSet:
    """Bundle of ADK-compatible callbacks returned by :func:`make_sentinel_callbacks`."""

    before_model: Callable[..., Any]
    after_model: Callable[..., Any]
    before_tool: Callable[..., Any]
    after_tool: Callable[..., Any]
    mode: Mode = "enforce"
    on_violation: Optional[Callable[[str, ScanResult], None]] = None
    history: list[dict] = field(default_factory=list)

    def apply_to(self, agent: Any) -> Any:
        """Attach callbacks to a Google ADK ``Agent`` instance."""
        try:
            # Google ADK exposes these attribute names on agents.
            agent.before_model_callback = self.before_model
            agent.after_model_callback = self.after_model
            agent.before_tool_callback = self.before_tool
            agent.after_tool_callback = self.after_tool
        except AttributeError as exc:
            raise TypeError(f"Object {agent!r} is not a Google ADK agent") from exc
        return agent


def make_sentinel_callbacks(
    mode: Mode = "enforce",
    input_scanners: list[str] | None = None,
    output_scanners: list[str] | None = None,
    on_violation: Optional[Callable[[str, ScanResult], None]] = None,
    block_message: str = "Sentinel blocked this request.",
) -> ADKCallbackSet:
    """Build an :class:`ADKCallbackSet` bound to a shared middleware."""
    mw = SentinelMiddleware(
        input_scanners=input_scanners,
        output_scanners=output_scanners,
        block_message=block_message,
    )

    history: list[dict] = []

    def _record(phase: str, result: ScanResult) -> None:
        history.append({
            "phase": phase,
            "action": result.action.value,
            "risk_score": getattr(result, "risk_score", 0.0),
            "findings": len(result.findings),
        })

    def _violate(phase: str, result: ScanResult) -> bool:
        _record(phase, result)
        if on_violation:
            try:
                on_violation(phase, result)
            except Exception:  # pragma: no cover - user callback
                logger.exception("on_violation callback raised")
        if mode == "enforce" and result.action == ScanAction.BLOCK:
            return True
        return False

    def before_model(llm_request: Any, **_: Any) -> Any:
        if mode == "off":
            return None
        prompt = _extract_prompt(llm_request)
        result = mw.guard_input(prompt)
        if _violate("before_model", result):
            return {"blocked": True, "reason": block_message, "findings": len(result.findings)}
        _maybe_replace_prompt(llm_request, result.sanitized)
        return None

    def after_model(llm_response: Any, **_: Any) -> Any:
        if mode == "off":
            return None
        text = _extract_response(llm_response)
        result = mw.guard_output("", text)
        if _violate("after_model", result):
            return {"blocked": True, "reason": block_message, "findings": len(result.findings)}
        _maybe_replace_response(llm_response, result.sanitized)
        return None

    def before_tool(tool: Any, args: dict, **_: Any) -> Any:
        if mode == "off":
            return None
        payload = f"tool={getattr(tool, 'name', repr(tool))} args={args!r}"
        result = mw.guard_input(payload)
        if _violate("before_tool", result):
            return {"blocked": True, "reason": block_message}
        return None

    def after_tool(tool: Any, result_obj: Any, **_: Any) -> Any:
        if mode == "off":
            return None
        text = str(result_obj)[:8000]
        scan = mw.guard_output("", text)
        if _violate("after_tool", scan):
            return {"blocked": True, "reason": block_message}
        return None

    return ADKCallbackSet(
        before_model=before_model,
        after_model=after_model,
        before_tool=before_tool,
        after_tool=after_tool,
        mode=mode,
        on_violation=on_violation,
        history=history,
    )


# ---------------------------------------------------------------------------
# helpers -------------------------------------------------------------------
# ---------------------------------------------------------------------------
def _extract_prompt(request: Any) -> str:
    """Best-effort extraction of the user prompt from an ADK ``LlmRequest``."""
    if request is None:
        return ""
    for attr in ("contents", "messages", "prompt", "input", "text"):
        value = getattr(request, attr, None)
        if value is None:
            continue
        if isinstance(value, str):
            return value
        try:
            return "\n".join(
                getattr(m, "text", None) or getattr(m, "content", None) or str(m)
                for m in value
            )
        except Exception:
            return str(value)
    return str(request)


def _extract_response(response: Any) -> str:
    if response is None:
        return ""
    for attr in ("text", "output_text", "content"):
        value = getattr(response, attr, None)
        if isinstance(value, str):
            return value
    try:
        candidates = getattr(response, "candidates", None) or []
        out = []
        for c in candidates:
            parts = getattr(c, "content", None)
            if parts is not None:
                out.append(getattr(parts, "text", str(parts)))
        if out:
            return "\n".join(out)
    except Exception:
        pass
    return str(response)


def _maybe_replace_prompt(request: Any, sanitized: str) -> None:
    if isinstance(sanitized, str) and hasattr(request, "prompt"):
        try:
            request.prompt = sanitized
        except Exception:
            pass


def _maybe_replace_response(response: Any, sanitized: str) -> None:
    if isinstance(sanitized, str) and hasattr(response, "text"):
        try:
            response.text = sanitized
        except Exception:
            pass


class SentinelADKPlugin:
    """Convenience wrapper used with ADK Plugin architecture."""

    def __init__(self, mode: Mode = "enforce", **kwargs: Any) -> None:
        self.callbacks = make_sentinel_callbacks(mode=mode, **kwargs)

    def apply_to(self, agent: Any) -> Any:
        return self.callbacks.apply_to(agent)

    @property
    def history(self) -> list[dict]:
        return self.callbacks.history
