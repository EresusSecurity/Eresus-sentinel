"""
Echo Generator — deterministic test generator with advanced simulation modes.

Production-grade features:
  - Prefix/suffix decoration
  - Template substitution ($INPUT, $MODEL, $TURN, $TIMESTAMP)
  - Configurable latency simulation
  - Token counting simulation
  - Canned response mode (round-robin or random)
  - Failure injection (for testing retry logic)
  - Multi-turn echo with conversation history
"""

from __future__ import annotations

import hashlib
import logging
import random
import time
from typing import Optional

from sentinel.redteam.generators.base import Generator, GeneratorConfig, GeneratorResponse

logger = logging.getLogger(__name__)


class EchoGenerator(Generator):
    """
    Deterministic test generator — returns predictable responses.

    Modes:
      - echo: Returns last message with optional prefix/suffix
      - template: Substitutes variables in template string
      - canned: Returns from a list of pre-defined responses
      - history: Returns full conversation history as response
      - fail: Raises exception (for testing retry/error handling)

    Usage:
        # Simple echo
        gen = EchoGenerator()
        resp = gen.generate("Hello")  # → "Hello"

        # Template mode
        gen = EchoGenerator(mode="template", template="Received: '$INPUT' at turn $TURN")

        # Canned responses (round-robin)
        gen = EchoGenerator(mode="canned", responses=["Yes", "No", "Maybe"])

        # Failure injection (50% chance)
        gen = EchoGenerator(mode="fail", fail_rate=0.5)
    """

    name = "echo"
    provider = "test"

    def __init__(self, config: Optional[GeneratorConfig] = None, **kwargs):
        super().__init__(config, **kwargs)
        self._prefix = kwargs.get("prefix", "")
        self._suffix = kwargs.get("suffix", "")
        self._mode = kwargs.get("mode", "echo")
        self._template = kwargs.get("template", "$INPUT")
        self._responses = kwargs.get("responses", [])
        self._response_idx = 0
        self._latency_ms = kwargs.get("latency_ms", 0)
        self._fail_rate = kwargs.get("fail_rate", 0.0)
        self._fail_error = kwargs.get("fail_error", "Simulated failure")
        self._turn_counter = 0
        self._simulate_tokens = kwargs.get("simulate_tokens", True)

    def _call_api(self, messages: list[dict], **kwargs) -> GeneratorResponse:
        self._turn_counter += 1
        start = time.time()

        # Simulated latency
        if self._latency_ms > 0:
            time.sleep(self._latency_ms / 1000.0)

        # Failure injection
        if self._fail_rate > 0 and random.random() < self._fail_rate:
            raise RuntimeError(self._fail_error)

        last_msg = messages[-1]["content"] if messages else ""

        # Mode dispatch
        if self._mode == "template":
            text = self._render_template(last_msg, messages)
        elif self._mode == "canned":
            text = self._canned_response()
        elif self._mode == "history":
            text = self._history_response(messages)
        elif self._mode == "hash":
            text = self._hash_response(last_msg)
        elif self._mode == "fail":
            raise RuntimeError(self._fail_error)
        else:
            text = f"{self._prefix}{last_msg}{self._suffix}"

        elapsed_ms = (time.time() - start) * 1000

        # Simulate token counting
        input_tokens = sum(len(m["content"].split()) for m in messages) if self._simulate_tokens else 0
        output_tokens = len(text.split()) if self._simulate_tokens else 0

        return GeneratorResponse(
            text=text,
            model=f"echo-{self._mode}",
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=input_tokens + output_tokens,
            finish_reason="stop",
            raw={
                "mode": self._mode,
                "turn": self._turn_counter,
                "latency_ms": round(elapsed_ms, 2),
                "messages_count": len(messages),
            },
        )

    def _render_template(self, last_msg: str, messages: list[dict]) -> str:
        """Render template with variable substitution."""
        text = self._template
        text = text.replace("$INPUT", last_msg)
        text = text.replace("$MODEL", "echo")
        text = text.replace("$TURN", str(self._turn_counter))
        text = text.replace("$TIMESTAMP", str(int(time.time())))
        text = text.replace("$MSG_COUNT", str(len(messages)))
        text = text.replace("$WORD_COUNT", str(len(last_msg.split())))
        return text

    def _canned_response(self) -> str:
        """Return next canned response (round-robin)."""
        if not self._responses:
            return "No canned responses configured"
        response = self._responses[self._response_idx % len(self._responses)]
        self._response_idx += 1
        return response

    def _history_response(self, messages: list[dict]) -> str:
        """Return full conversation history."""
        lines = []
        for m in messages:
            role = m.get("role", "unknown")
            content = m.get("content", "")
            lines.append(f"[{role}] {content}")
        return "\n".join(lines)

    def _hash_response(self, text: str) -> str:
        """Return deterministic hash-based response."""
        h = hashlib.sha256(text.encode()).hexdigest()[:16]
        return f"ECHO-{h}-TURN{self._turn_counter}"

    @property
    def turn_counter(self) -> int:
        """Number of generate() calls made."""
        return self._turn_counter

    def reset(self):
        """Reset counters."""
        self._turn_counter = 0
        self._response_idx = 0
