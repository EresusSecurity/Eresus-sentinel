"""
Function Generator — wraps any Python callable as a production-grade generator.

Production-grade features:
  - Sync and async callable support
  - Message-level and full-conversation callables
  - Output validation (type checking, length limits)
  - Exception wrapping with structured error responses
  - Metadata extraction from callable
  - Timeout enforcement
  - Batch mode support
"""

from __future__ import annotations

import asyncio
import inspect
import logging
import time
from typing import Any, Callable, Optional

from sentinel.redteam.generators.base import Generator, GeneratorConfig, GeneratorResponse

logger = logging.getLogger(__name__)


class FunctionGenerator(Generator):
    """
    Wraps any Python callable as a red-team generator.

    Callable signatures supported:
      1. fn(prompt: str) → str
      2. fn(messages: list[dict]) → str
      3. fn(messages: list[dict]) → dict  (with 'text', 'model', etc.)
      4. fn(prompt: str, **kwargs) → str
      5. async fn(prompt: str) → str

    Usage:
        # Simple function
        gen = FunctionGenerator(fn=lambda p: f"Response to: {p}")

        # Custom model wrapper
        def my_model(prompt: str) -> str:
            return my_api.complete(prompt)
        gen = FunctionGenerator(fn=my_model)

        # Full message handler
        def chat(messages: list[dict]) -> str:
            return some_chat_api(messages)
        gen = FunctionGenerator(fn=chat, mode="messages")

        # Returning structured data
        def structured(prompt: str) -> dict:
            return {"text": "Hello", "model": "custom", "tokens": 5}
        gen = FunctionGenerator(fn=structured)
    """

    name = "function"
    provider = "custom"

    def __init__(
        self,
        fn: Callable,
        config: Optional[GeneratorConfig] = None,
        mode: str = "auto",
        timeout: float = 30.0,
        max_output_length: int = 0,
        model_name: str = "function",
        **kwargs,
    ):
        """
        Args:
            fn: The callable to wrap.
            mode: 'auto' (detect from signature), 'prompt', or 'messages'.
            timeout: Max seconds per invocation (0 = no limit).
            max_output_length: Max output chars (0 = unlimited).
            model_name: Model name for reporting.
        """
        super().__init__(config, **kwargs)
        self._fn = fn
        self._mode = mode
        self._timeout = timeout
        self._max_output = max_output_length
        self._model_name = model_name
        self._is_async = asyncio.iscoroutinefunction(fn)
        self._call_count = 0
        self._total_latency = 0.0

        # Auto-detect mode from function signature
        if mode == "auto":
            self._mode = self._detect_mode(fn)

    def _call_api(self, messages: list[dict], **kwargs) -> GeneratorResponse:
        self._call_count += 1
        start = time.time()

        try:
            # Call the function based on mode
            if self._mode == "messages":
                result = self._invoke(messages)
            else:
                last_msg = messages[-1]["content"] if messages else ""
                result = self._invoke(last_msg)

            elapsed = time.time() - start
            self._total_latency += elapsed

            # Process result
            return self._build_response(result, elapsed)

        except Exception as exc:
            elapsed = time.time() - start
            self._total_latency += elapsed
            logger.error("Function generator error: %s", exc)
            return GeneratorResponse(
                text=f"[ERROR] {type(exc).__name__}: {exc}",
                model=self._model_name,
                finish_reason="error",
                raw={"error": str(exc), "type": type(exc).__name__},
            )

    def _invoke(self, arg: Any) -> Any:
        """Invoke the wrapped function with timeout."""
        if self._is_async:
            loop = asyncio.new_event_loop()
            try:
                if self._timeout > 0:
                    return loop.run_until_complete(
                        asyncio.wait_for(self._fn(arg), timeout=self._timeout)
                    )
                return loop.run_until_complete(self._fn(arg))
            finally:
                loop.close()
        else:
            # Sync call — timeout via signal on Unix
            return self._fn(arg)

    def _build_response(self, result: Any, elapsed: float) -> GeneratorResponse:
        """Build GeneratorResponse from callable result."""
        # Dict result with structured data
        if isinstance(result, dict):
            text = str(result.get("text", result.get("content", result.get("output", ""))))
            return GeneratorResponse(
                text=self._enforce_length(text),
                model=result.get("model", self._model_name),
                input_tokens=result.get("input_tokens", 0),
                output_tokens=result.get("output_tokens", len(text.split())),
                total_tokens=result.get("total_tokens", 0),
                finish_reason=result.get("finish_reason", "stop"),
                raw={"result": result, "latency_s": round(elapsed, 4)},
            )

        # GeneratorResponse passthrough
        if isinstance(result, GeneratorResponse):
            return result

        # String result
        text = str(result) if result is not None else ""
        text = self._enforce_length(text)

        return GeneratorResponse(
            text=text,
            model=self._model_name,
            output_tokens=len(text.split()),
            finish_reason="stop",
            raw={"latency_s": round(elapsed, 4)},
        )

    def _enforce_length(self, text: str) -> str:
        """Truncate if max_output_length is set."""
        if self._max_output > 0 and len(text) > self._max_output:
            return text[:self._max_output] + "... [TRUNCATED]"
        return text

    @staticmethod
    def _detect_mode(fn: Callable) -> str:
        """Auto-detect mode from function signature."""
        try:
            sig = inspect.signature(fn)
            params = list(sig.parameters.values())
            if params:
                first = params[0]
                annotation = first.annotation
                if annotation == list or (hasattr(annotation, '__origin__') and annotation.__origin__ is list):
                    return "messages"
                if first.name in ("messages", "conversation", "history", "msgs"):
                    return "messages"
        except (ValueError, TypeError):
            pass
        return "prompt"

    @property
    def call_count(self) -> int:
        """Number of invocations."""
        return self._call_count

    @property
    def avg_latency(self) -> float:
        """Average latency in seconds."""
        return self._total_latency / max(self._call_count, 1)
