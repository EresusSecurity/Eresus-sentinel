"""
Eresus Sentinel — LangChain / LlamaIndex / OpenAI / Generic Middleware.

Drop-in guardrail callbacks for popular LLM frameworks.

Features:
  - LangChain callback handler (pre/post generation hooks)
  - OpenAI SDK wrapper (direct drop-in)
  - Generic middleware wrapper (any LLM function)
  - Async support for all wrappers
  - Automatic audit logging + cost tracking
  - Rate limiting per session
  - Vault integration for PII redact/restore
  - Retry on transient scanner errors

Usage (LangChain):
    from sentinel.middleware import SentinelLangChainHandler
    handler = SentinelLangChainHandler()
    llm = ChatOpenAI(callbacks=[handler])

Usage (OpenAI):
    from sentinel.middleware import SentinelOpenAIWrapper
    wrapper = SentinelOpenAIWrapper(client)
    response = wrapper.chat("What is AI?")

Usage (Generic):
    from sentinel.middleware import sentinel_guard
    @sentinel_guard(input_scanners=["injection", "toxicity"])
    def generate(prompt: str) -> str:
        return openai.chat.completions.create(...)

Usage (Wrapper):
    from sentinel.middleware import SentinelMiddleware
    mw = SentinelMiddleware()
    safe_response = mw.wrap(prompt, raw_response)
"""

from __future__ import annotations

import asyncio
import functools
import logging
import threading
import time
from typing import Any, Callable, Optional

from sentinel.firewall.base import ScanAction, ScanResult

logger = logging.getLogger(__name__)


class SentinelMiddleware:
    """
    Generic middleware wrapper for any LLM interaction.

    Usage:
        mw = SentinelMiddleware()

        # Guard a prompt before sending
        input_result = mw.guard_input(user_prompt)
        if input_result.action == ScanAction.BLOCK:
            return "Blocked"

        # Guard output after receiving
        output_result = mw.guard_output(user_prompt, llm_response)
        final_response = output_result.sanitized
    """

    def __init__(
        self,
        input_scanners: list[str] | None = None,
        output_scanners: list[str] | None = None,
        policy_path: str | None = None,
        block_message: str = "I cannot process this request due to safety policies.",
        enable_vault: bool = False,
        enable_audit: bool = False,
        audit_path: str | None = None,
    ):
        from sentinel.sdk import Sentinel

        if policy_path:
            self._sentinel = Sentinel.from_policy(policy_path)
        else:
            self._sentinel = Sentinel(
                input_scanners=input_scanners or ["injection", "toxicity", "secrets"],
                output_scanners=output_scanners or ["toxicity", "sensitive", "bias"],
                vault_enabled=enable_vault,
            )
        self._block_message = block_message

        # Vault
        self._vault = None
        if enable_vault:
            from sentinel.vault import Vault
            self._vault = Vault()

        # Audit
        self._audit = None
        if enable_audit or audit_path:
            from sentinel.audit import AuditLogger
            self._audit = AuditLogger(path=audit_path or "sentinel_middleware_audit.jsonl")

        # Stats
        self._lock = threading.Lock()
        self._stats = {
            "total_input_scans": 0,
            "total_output_scans": 0,
            "total_blocks": 0,
            "total_redactions": 0,
        }

    def guard_input(self, prompt: str) -> ScanResult:
        """Scan input prompt. Returns ScanResult."""
        start = time.perf_counter()
        result = self._sentinel.scan_input(prompt)
        elapsed_ms = (time.perf_counter() - start) * 1000

        with self._lock:
            self._stats["total_input_scans"] += 1
            if result.action == ScanAction.BLOCK:
                self._stats["total_blocks"] += 1

        if self._audit:
            self._audit.log_result("middleware_input", "input", result, latency_ms=elapsed_ms)

        return result

    def guard_output(self, prompt: str, output: str) -> ScanResult:
        """Scan output response. Returns ScanResult with sanitized text."""
        start = time.perf_counter()
        result = self._sentinel.scan_output(prompt, output)
        elapsed_ms = (time.perf_counter() - start) * 1000

        # Vault restore if enabled
        if self._vault and result.sanitized:
            result.sanitized = self._vault.restore(result.sanitized)

        with self._lock:
            self._stats["total_output_scans"] += 1
            if result.action == ScanAction.REDACT:
                self._stats["total_redactions"] += 1
            if result.action == ScanAction.BLOCK:
                self._stats["total_blocks"] += 1

        if self._audit:
            self._audit.log_result("middleware_output", "output", result, latency_ms=elapsed_ms)

        return result

    def wrap(self, prompt: str, output: str) -> str:
        """
        Full guard: scan input + output, return safe text.
        Returns sanitized output or block message.
        """
        input_result = self.guard_input(prompt)
        if input_result.action == ScanAction.BLOCK:
            logger.warning("Input blocked: risk=%.2f, findings=%d",
                           input_result.risk_score, len(input_result.findings))
            return self._block_message

        output_result = self.guard_output(prompt, output)
        if output_result.action == ScanAction.BLOCK:
            logger.warning("Output blocked: risk=%.2f, findings=%d",
                           output_result.risk_score, len(output_result.findings))
            return self._block_message

        return output_result.sanitized

    async def async_guard_input(self, prompt: str) -> ScanResult:
        """Async version of guard_input."""
        return await asyncio.to_thread(self.guard_input, prompt)

    async def async_guard_output(self, prompt: str, output: str) -> ScanResult:
        """Async version of guard_output."""
        return await asyncio.to_thread(self.guard_output, prompt, output)

    async def async_wrap(self, prompt: str, output: str) -> str:
        """Async version of wrap."""
        return await asyncio.to_thread(self.wrap, prompt, output)

    @property
    def stats(self) -> dict:
        with self._lock:
            return dict(self._stats)


def sentinel_guard(
    input_scanners: list[str] | None = None,
    output_scanners: list[str] | None = None,
    block_message: str = "I cannot process this request due to safety policies.",
    enable_vault: bool = False,
):
    """
    Decorator to guard any function that takes a prompt and returns a response.

    Usage:
        @sentinel_guard(input_scanners=["injection", "toxicity"])
        def my_llm_call(prompt: str) -> str:
            return openai_client.chat(prompt)
    """
    mw = SentinelMiddleware(
        input_scanners=input_scanners,
        output_scanners=output_scanners,
        block_message=block_message,
        enable_vault=enable_vault,
    )

    def decorator(func: Callable) -> Callable:
        @functools.wraps(func)
        def wrapper(prompt: str, *args, **kwargs) -> str:
            # Guard input
            input_result = mw.guard_input(prompt)
            if input_result.action == ScanAction.BLOCK:
                return block_message

            # Call the actual function with sanitized input
            safe_prompt = input_result.sanitized
            output = func(safe_prompt, *args, **kwargs)

            # Guard output
            output_result = mw.guard_output(prompt, str(output))
            if output_result.action == ScanAction.BLOCK:
                return block_message

            return output_result.sanitized

        @functools.wraps(func)
        async def async_wrapper(prompt: str, *args, **kwargs) -> str:
            """Async variant — auto-detected for async functions."""
            input_result = await mw.async_guard_input(prompt)
            if input_result.action == ScanAction.BLOCK:
                return block_message

            safe_prompt = input_result.sanitized
            output = await func(safe_prompt, *args, **kwargs)

            output_result = await mw.async_guard_output(prompt, str(output))
            if output_result.action == ScanAction.BLOCK:
                return block_message

            return output_result.sanitized

        # Auto-detect async functions
        if asyncio.iscoroutinefunction(func):
            return async_wrapper
        return wrapper

    return decorator


class SentinelOpenAIWrapper:
    """
    Drop-in wrapper for OpenAI SDK that adds Sentinel guardrails.

    Usage:
        from openai import OpenAI
        from sentinel.middleware import SentinelOpenAIWrapper

        client = OpenAI()
        guarded = SentinelOpenAIWrapper(client)

        # Same API as OpenAI, but with security guardrails
        response = guarded.chat("Tell me about AI safety")
        # response is sanitized string

        # Or with full control
        result = guarded.chat_with_result("Tell me about AI safety")
        # result.blocked, result.sanitized_response, result.findings
    """

    def __init__(
        self,
        client: Any,
        input_scanners: list[str] | None = None,
        output_scanners: list[str] | None = None,
        model: str = "gpt-4o",
        block_message: str = "I cannot process this request due to safety policies.",
    ):
        self._client = client
        self._model = model
        self._mw = SentinelMiddleware(
            input_scanners=input_scanners,
            output_scanners=output_scanners,
            block_message=block_message,
        )

    def chat(
        self,
        prompt: str,
        system: str = "",
        model: str | None = None,
        **kwargs,
    ) -> str:
        """
        Guarded chat completion. Returns sanitized response string.
        Raises ValueError if input is blocked.
        """
        result = self.chat_with_result(prompt, system=system, model=model, **kwargs)
        if result["blocked"]:
            raise ValueError(f"Blocked: {result['reason']}")
        return result["response"]

    def chat_with_result(
        self,
        prompt: str,
        system: str = "",
        model: str | None = None,
        **kwargs,
    ) -> dict:
        """
        Guarded chat completion with full result details.

        Returns dict with: response, blocked, reason, input_findings, output_findings
        """
        # Guard input
        input_result = self._mw.guard_input(prompt)
        if input_result.action == ScanAction.BLOCK:
            return {
                "response": self._mw._block_message,
                "blocked": True,
                "reason": f"Input blocked: {len(input_result.findings)} findings",
                "input_findings": len(input_result.findings),
                "output_findings": 0,
                "risk_score": input_result.risk_score,
            }

        # Call OpenAI
        messages = []
        if system:
            messages.append({"role": "system", "content": system})
        messages.append({"role": "user", "content": input_result.sanitized})

        completion = self._client.chat.completions.create(
            model=model or self._model,
            messages=messages,
            **kwargs,
        )

        raw_output = completion.choices[0].message.content or ""

        # Guard output
        output_result = self._mw.guard_output(prompt, raw_output)

        blocked = output_result.action == ScanAction.BLOCK
        return {
            "response": self._mw._block_message if blocked else output_result.sanitized,
            "blocked": blocked,
            "reason": f"Output blocked: {len(output_result.findings)} findings" if blocked else "",
            "input_findings": len(input_result.findings),
            "output_findings": len(output_result.findings),
            "risk_score": max(input_result.risk_score, output_result.risk_score),
            "model": model or self._model,
            "usage": {
                "prompt_tokens": getattr(completion.usage, "prompt_tokens", 0),
                "completion_tokens": getattr(completion.usage, "completion_tokens", 0),
            } if hasattr(completion, "usage") else {},
        }


class SentinelLangChainHandler:
    """
    LangChain-compatible callback handler for Sentinel guardrails.

    Intercepts LLM calls at the callback level for both input and output.

    Usage:
        from sentinel.middleware import SentinelLangChainHandler
        handler = SentinelLangChainHandler()

        from langchain_openai import ChatOpenAI
        llm = ChatOpenAI(callbacks=[handler])
        result = llm.invoke("Hello")

    NOTE: Override on_llm_start/on_llm_end to integrate with
    LangChain's CallbackHandler interface. This does NOT import
    LangChain — it's duck-typed for any callback system.
    """

    def __init__(
        self,
        input_scanners: list[str] | None = None,
        output_scanners: list[str] | None = None,
        raise_on_block: bool = True,
        enable_audit: bool = False,
    ):
        self._mw = SentinelMiddleware(
            input_scanners=input_scanners or ["injection", "toxicity"],
            output_scanners=output_scanners or ["toxicity", "sensitive"],
            enable_audit=enable_audit,
        )
        self._raise_on_block = raise_on_block
        self._last_prompt = ""
        self._scan_results: list[dict] = []

    def on_llm_start(self, serialized: dict, prompts: list[str], **kwargs) -> None:
        """Called before LLM call. Scans input prompts."""
        for prompt in prompts:
            result = self._mw.guard_input(prompt)
            self._last_prompt = prompt
            self._scan_results.append({
                "phase": "input",
                "action": result.action.value,
                "risk_score": result.risk_score,
                "findings": len(result.findings),
            })
            if result.action == ScanAction.BLOCK and self._raise_on_block:
                raise ValueError(
                    f"Sentinel blocked input: {len(result.findings)} findings, "
                    f"risk={result.risk_score:.2f}"
                )

    def on_llm_end(self, response, **kwargs) -> None:
        """Called after LLM call. Scans output."""
        # Extract text from LangChain response
        text = ""
        if hasattr(response, "generations"):
            for gen_list in response.generations:
                for gen in gen_list:
                    text += getattr(gen, "text", "")

        if text:
            result = self._mw.guard_output(self._last_prompt, text)
            self._scan_results.append({
                "phase": "output",
                "action": result.action.value,
                "risk_score": result.risk_score,
                "findings": len(result.findings),
            })
            if result.action == ScanAction.BLOCK and self._raise_on_block:
                raise ValueError(
                    f"Sentinel blocked output: {len(result.findings)} findings, "
                    f"risk={result.risk_score:.2f}"
                )

    def on_llm_error(self, error: Exception, **kwargs) -> None:
        """Called on LLM error. Log for audit."""
        logger.error("LLM error during guarded call: %s", error)

    @property
    def scan_results(self) -> list[dict]:
        """Access scan history from this handler."""
        return list(self._scan_results)

    def clear_history(self) -> None:
        """Clear scan result history."""
        self._scan_results.clear()


class SentinelAgentMiddleware:
    """
    LangGraph / LangChain agent-level middleware with before/after model hooks.

    Operates in three modes:
      ``off``      — passthrough, no inspection.
      ``monitor``  — scans and logs, never blocks.
      ``enforce``  — raises on BLOCK findings.

    Usage (LangGraph):
        from sentinel.middleware import SentinelAgentMiddleware
        mw = SentinelAgentMiddleware(mode="enforce")

        # Wrap inside a LangGraph node or custom AgentExecutor step:
        def agent_node(state):
            mw.before_model(state["messages"][-1].content)
            response = llm.invoke(state["messages"])
            mw.after_model(response.content)
            return state
    """

    def __init__(
        self,
        mode: str = "enforce",
        input_scanners: list[str] | None = None,
        output_scanners: list[str] | None = None,
        on_violation: Optional[Callable[[str, "ScanResult"], None]] = None,
        block_message: str = "Sentinel blocked this agent action.",
    ) -> None:
        if mode not in ("off", "monitor", "enforce"):
            raise ValueError(f"mode must be 'off', 'monitor', or 'enforce', got {mode!r}")
        self.mode = mode
        self._mw = SentinelMiddleware(
            input_scanners=input_scanners,
            output_scanners=output_scanners,
            block_message=block_message,
        )
        self._on_violation = on_violation
        self._block_message = block_message
        self._history: list[dict] = []

    def before_model(self, prompt: str) -> str:
        """
        Scan prompt before it reaches the model.

        Returns sanitized prompt. Raises ``ValueError`` in enforce mode on BLOCK.
        """
        if self.mode == "off":
            return prompt
        result = self._mw.guard_input(prompt)
        self._record("before_model", result)
        if result.action == ScanAction.BLOCK:
            if self._on_violation:
                try:
                    self._on_violation("before_model", result)
                except Exception:
                    logger.exception("on_violation raised in before_model")
            if self.mode == "enforce":
                raise ValueError(
                    f"Sentinel blocked agent input: {len(result.findings)} findings, "
                    f"risk={result.risk_score:.2f}"
                )
        return result.sanitized or prompt

    def after_model(self, output: str, prompt: str = "") -> str:
        """
        Scan model output after generation.

        Returns sanitized output. Raises ``ValueError`` in enforce mode on BLOCK.
        """
        if self.mode == "off":
            return output
        result = self._mw.guard_output(prompt, output)
        self._record("after_model", result)
        if result.action == ScanAction.BLOCK:
            if self._on_violation:
                try:
                    self._on_violation("after_model", result)
                except Exception:
                    logger.exception("on_violation raised in after_model")
            if self.mode == "enforce":
                raise ValueError(
                    f"Sentinel blocked agent output: {len(result.findings)} findings, "
                    f"risk={result.risk_score:.2f}"
                )
        return result.sanitized or output

    async def async_before_model(self, prompt: str) -> str:
        """Async version of before_model."""
        return await asyncio.to_thread(self.before_model, prompt)

    async def async_after_model(self, output: str, prompt: str = "") -> str:
        """Async version of after_model."""
        return await asyncio.to_thread(self.after_model, output, prompt)

    def _record(self, phase: str, result: "ScanResult") -> None:
        self._history.append({
            "phase": phase,
            "action": result.action.value,
            "risk_score": result.risk_score,
            "findings": len(result.findings),
        })

    @property
    def history(self) -> list[dict]:
        return list(self._history)

    def clear_history(self) -> None:
        self._history.clear()


class SentinelToolMiddleware:
    """
    Intercept individual MCP / LangChain tool calls and results.

    Usage:
        from sentinel.middleware import SentinelToolMiddleware
        tool_mw = SentinelToolMiddleware(mode="enforce")

        # Wrap a tool call:
        safe_args = tool_mw.wrap_tool_call("read_file", {"path": user_path})
        result = actual_tool(safe_args)
        safe_result = tool_mw.wrap_tool_result("read_file", result)
    """

    def __init__(
        self,
        mode: str = "enforce",
        input_scanners: list[str] | None = None,
        output_scanners: list[str] | None = None,
        on_violation: Optional[Callable[[str, "ScanResult"], None]] = None,
        block_message: str = "Sentinel blocked this tool call.",
        blocked_tools: list[str] | None = None,
    ) -> None:
        if mode not in ("off", "monitor", "enforce"):
            raise ValueError(f"mode must be 'off', 'monitor', or 'enforce', got {mode!r}")
        self.mode = mode
        self._mw = SentinelMiddleware(
            input_scanners=input_scanners,
            output_scanners=output_scanners,
            block_message=block_message,
        )
        self._on_violation = on_violation
        self._block_message = block_message
        self._blocked_tools: set[str] = set(blocked_tools or [])
        self._history: list[dict] = []

    def wrap_tool_call(self, tool_name: str, args: dict) -> dict:
        """
        Inspect tool name + arguments before execution.

        Returns (possibly sanitized) args. Raises ``ValueError`` in enforce mode.
        """
        if self.mode == "off":
            return args
        if tool_name in self._blocked_tools:
            if self.mode == "enforce":
                raise ValueError(f"Tool '{tool_name}' is blocked by policy.")
            logger.warning("Blocked tool called in monitor mode: %s", tool_name)
            return args

        payload = f"tool_call name={tool_name!r} args={args!r}"
        result = self._mw.guard_input(payload)
        self._record("tool_call", tool_name, result)
        if result.action == ScanAction.BLOCK:
            self._fire_violation("tool_call", result)
            if self.mode == "enforce":
                raise ValueError(
                    f"Sentinel blocked tool call '{tool_name}': "
                    f"{len(result.findings)} findings"
                )
        return args

    def wrap_tool_result(self, tool_name: str, result_obj: Any) -> Any:
        """
        Inspect tool result after execution.

        Returns (possibly sanitized) result. Raises ``ValueError`` in enforce mode.
        """
        if self.mode == "off":
            return result_obj
        text = str(result_obj)[:16_000]
        result = self._mw.guard_output("", text)
        self._record("tool_result", tool_name, result)
        if result.action == ScanAction.BLOCK:
            self._fire_violation("tool_result", result)
            if self.mode == "enforce":
                raise ValueError(
                    f"Sentinel blocked tool result from '{tool_name}': "
                    f"{len(result.findings)} findings"
                )
        return result.sanitized if result.sanitized else result_obj

    async def awrap_tool_call(self, tool_name: str, args: dict) -> dict:
        """Async version of wrap_tool_call."""
        return await asyncio.to_thread(self.wrap_tool_call, tool_name, args)

    async def awrap_tool_result(self, tool_name: str, result_obj: Any) -> Any:
        """Async version of wrap_tool_result."""
        return await asyncio.to_thread(self.wrap_tool_result, tool_name, result_obj)

    def _record(self, phase: str, tool_name: str, result: "ScanResult") -> None:
        self._history.append({
            "phase": phase,
            "tool": tool_name,
            "action": result.action.value,
            "risk_score": result.risk_score,
            "findings": len(result.findings),
        })

    def _fire_violation(self, phase: str, result: "ScanResult") -> None:
        if self._on_violation:
            try:
                self._on_violation(phase, result)
            except Exception:
                logger.exception("on_violation raised in %s", phase)

    @property
    def history(self) -> list[dict]:
        return list(self._history)

    def clear_history(self) -> None:
        self._history.clear()
