"""
Base Generator — all LLM generators inherit from this.

Features:
  - Automatic retry with exponential backoff
  - Rate limiting with token bucket
  - Response caching (optional)
  - Usage tracking (tokens, cost)
  - System prompt injection
  - Multi-turn conversation support
  - Streaming support (optional)
"""

from __future__ import annotations

import hashlib
import logging
import time
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


def _mask_key(key: str | None) -> str:
    """Mask an API key for safe logging — shows only first 4 and last 4 chars."""
    if not key:
        return "(not set)"
    if len(key) <= 8:
        return "***"
    return f"{key[:4]}...{key[-4:]}"


def _sanitize_error(exc: Exception) -> str:
    """Remove potential API key / token values from exception messages."""
    import re
    msg = str(exc)
    # Redact anything that looks like a bearer token or sk-... key
    msg = re.sub(r"sk-[A-Za-z0-9_-]{8,}", "sk-***", msg)
    msg = re.sub(r"Bearer [A-Za-z0-9_\-\.]+", "Bearer ***", msg)
    msg = re.sub(r"api[_-]?key[=:\s]+[A-Za-z0-9_\-]{8,}", "api_key=***", msg, flags=re.IGNORECASE)
    return msg


@dataclass
class GeneratorResponse:
    """Standardized response from any generator."""
    text: str
    model: str = ""
    provider: str = ""
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    latency_ms: float = 0.0
    finish_reason: str = ""
    raw: Any = None
    cached: bool = False

    @property
    def estimated_cost_usd(self) -> float:
        """Rough cost estimate based on token counts (per 1M tokens, April 2026)."""
        prices = {
            # OpenAI GPT-5.4 series (March 2026)
            "gpt-5.4": (2.50, 15.00),
            "gpt-5.4-pro": (30.00, 180.00),
            "gpt-5.4-mini": (0.75, 4.50),
            "gpt-5.4-nano": (0.20, 1.25),
            # OpenAI GPT-5.3 Codex (Feb 2026)
            "gpt-5.3-codex": (3.00, 12.00),
            # OpenAI GPT-5.2 (Dec 2025)
            "gpt-5.2": (2.00, 10.00),
            # OpenAI GPT-OSS open-weight (Aug 2025)
            "gpt-oss-120b": (0.15, 0.60),
            "gpt-oss-20b": (0.075, 0.30),
            # OpenAI legacy (still available)
            "gpt-4o": (2.50, 10.00),
            "gpt-4o-mini": (0.15, 0.60),
            "o4-mini": (1.10, 4.40),
            "o3": (2.00, 8.00),
            "o3-mini": (1.10, 4.40),
            # Anthropic Claude 4.6 series (2026)
            "claude-opus-4-6": (5.00, 25.00),
            "claude-sonnet-4-6": (3.00, 15.00),
            "claude-haiku-4-5": (1.00, 5.00),
            # Anthropic Claude 4.x legacy
            "claude-sonnet-4-20250514": (3.00, 15.00),
            "claude-opus-4-20250514": (5.00, 25.00),
            # Google Gemini 3.x series (2026)
            "gemini-3.1-pro-preview": (2.00, 12.00),
            "gemini-3-flash": (0.10, 0.40),
            "gemini-3.1-flash-lite": (0.05, 0.20),
            # Google Gemini 2.x legacy
            "gemini-2.5-pro": (1.25, 10.00),
            "gemini-2.5-flash": (0.075, 0.30),
            # Groq (open-source models, April 2026)
            "llama-3.3-70b-versatile": (0.59, 0.79),
            "llama-4-scout-17bx16e": (0.11, 0.34),
            "llama-3.1-8b-instant": (0.05, 0.08),
            "qwen3-32b": (0.29, 0.59),
            # Together AI / open-source
            "meta-llama/Meta-Llama-3.3-70B-Instruct-Turbo": (0.59, 0.79),
            "deepseek-v3.1": (0.50, 2.00),
            "deepseek-r1": (0.75, 3.00),
            "qwen3.5-397b": (1.50, 6.00),
        }
        in_price, out_price = prices.get(self.model, (1.0, 3.0))
        return (self.input_tokens * in_price + self.output_tokens * out_price) / 1_000_000


@dataclass
class GeneratorConfig:
    """Configuration for a generator."""
    model: str = ""
    temperature: float = 0.7
    max_tokens: int = 1024
    top_p: float = 1.0
    frequency_penalty: float = 0.0
    presence_penalty: float = 0.0
    stop: list[str] = field(default_factory=list)
    system_prompt: Optional[str] = None
    timeout: int = 60
    max_retries: int = 3
    retry_delay: float = 1.0
    rate_limit_rpm: int = 60
    cache_responses: bool = False
    seed: Optional[int] = None


class Generator(ABC):
    """
    Base class for all LLM generators.

    Features:
      - Unified interface across 12+ providers
      - Automatic retries with exponential backoff
      - Built-in rate limiting
      - Response caching
      - Token/cost tracking
      - System prompt management
      - Multi-turn conversation support
    """

    name: str = "base"
    provider: str = "unknown"
    supports_system_prompt: bool = True
    supports_streaming: bool = False
    supports_multi_turn: bool = True

    def __init__(self, config: Optional[GeneratorConfig] = None, **kwargs):
        self.config = config or GeneratorConfig()
        # Override config with kwargs
        for k, v in kwargs.items():
            if hasattr(self.config, k):
                setattr(self.config, k, v)

        self._cache: dict[str, GeneratorResponse] = {}
        self._usage_total_tokens = 0
        self._usage_total_cost = 0.0
        self._request_count = 0
        self._last_request_time = 0.0
        self._conversation: list[dict] = []

    @abstractmethod
    def _call_api(self, messages: list[dict], **kwargs) -> GeneratorResponse:
        """Make the actual API call. Must be implemented by subclasses."""
        ...

    def generate(self, prompt: str, system_prompt: Optional[str] = None) -> GeneratorResponse:
        """Generate a response from a single prompt."""
        messages = []
        sys_prompt = system_prompt or self.config.system_prompt
        if sys_prompt and self.supports_system_prompt:
            messages.append({"role": "system", "content": sys_prompt})
        messages.append({"role": "user", "content": prompt})
        return self._execute(messages)

    def chat(self, messages: list[dict]) -> GeneratorResponse:
        """Generate from a full conversation."""
        return self._execute(messages)

    def continue_conversation(self, user_message: str) -> GeneratorResponse:
        """Continue an ongoing multi-turn conversation."""
        self._conversation.append({"role": "user", "content": user_message})
        response = self._execute(list(self._conversation))
        self._conversation.append({"role": "assistant", "content": response.text})
        return response

    def reset_conversation(self):
        """Reset multi-turn conversation state."""
        self._conversation.clear()

    def _execute(self, messages: list[dict]) -> GeneratorResponse:
        """Execute with retries, rate limiting, and caching."""
        # Check cache
        if self.config.cache_responses:
            cache_key = self._cache_key(messages)
            if cache_key in self._cache:
                resp = self._cache[cache_key]
                resp.cached = True
                return resp

        # Rate limiting
        self._enforce_rate_limit()

        # Retry loop
        last_error = None
        for attempt in range(self.config.max_retries + 1):
            try:
                start = time.monotonic()
                response = self._call_api(messages)
                response.latency_ms = (time.monotonic() - start) * 1000
                response.provider = self.provider
                if not response.model:
                    response.model = self.config.model

                # Track usage
                self._usage_total_tokens += response.total_tokens
                self._usage_total_cost += response.estimated_cost_usd
                self._request_count += 1

                # Cache
                if self.config.cache_responses:
                    self._cache[self._cache_key(messages)] = response

                return response

            except Exception as exc:
                last_error = exc
                if attempt < self.config.max_retries:
                    delay = self.config.retry_delay * (2 ** attempt)
                    logger.warning(
                        "Generator %s attempt %d/%d failed: %s. Retrying in %.1fs",
                        self.name, attempt + 1, self.config.max_retries,
                        _sanitize_error(exc), delay,
                    )
                    time.sleep(delay)

        raise RuntimeError(
            f"Generator {self.name} failed after {self.config.max_retries + 1} attempts: "
            f"{_sanitize_error(last_error)}"
        )

    def _enforce_rate_limit(self):
        """Simple rate limiting."""
        if self.config.rate_limit_rpm <= 0:
            return
        min_interval = 60.0 / self.config.rate_limit_rpm
        elapsed = time.monotonic() - self._last_request_time
        if elapsed < min_interval:
            time.sleep(min_interval - elapsed)
        self._last_request_time = time.monotonic()

    @staticmethod
    def _cache_key(messages: list[dict]) -> str:
        content = str(messages).encode()
        return hashlib.sha256(content).hexdigest()

    @property
    def usage(self) -> dict:
        """Return usage statistics."""
        return {
            "total_requests": self._request_count,
            "total_tokens": self._usage_total_tokens,
            "estimated_cost_usd": round(self._usage_total_cost, 6),
        }

    def __repr__(self) -> str:
        return f"{self.__class__.__name__}(model={self.config.model!r}, provider={self.provider!r})"
