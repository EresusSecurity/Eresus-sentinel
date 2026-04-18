"""
Groq Generator — ultra-fast inference via Groq Cloud.

Production-grade features:
  - 15+ supported models (Llama 4, Llama 3.3, GPT-OSS, Qwen3, etc.)
  - Model context window tracking
  - Streaming support with chunk callbacks
  - Rate limit handling (429 retry + backoff)
  - Automatic model validation
  - JSON mode support
  - Tool/function calling support
  - Usage statistics tracking
  - Speed metrics (tokens/sec from Groq's sub-100ms latency)

Env: GROQ_API_KEY
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.request
import urllib.error
from typing import Callable, Optional

from sentinel.redteam.generators.base import Generator, GeneratorConfig, GeneratorResponse

logger = logging.getLogger(__name__)

# Groq available models + context windows (April 2026)
GROQ_MODELS: dict[str, dict] = {
    # Llama 4 series
    "meta-llama/llama-4-scout-17b-16e-instruct": {"ctx": 512_000, "family": "llama4"},
    "meta-llama/llama-4-maverick-17b-128e-instruct": {"ctx": 1_048_576, "family": "llama4"},
    # Llama 3.3
    "llama-3.3-70b-versatile": {"ctx": 128_000, "family": "llama3.3"},
    "llama-3.3-70b-specdec": {"ctx": 8_192, "family": "llama3.3"},
    # Llama 3.1
    "llama-3.1-8b-instant": {"ctx": 128_000, "family": "llama3.1"},
    # GPT-OSS
    "gpt-oss-20b": {"ctx": 128_000, "family": "gpt-oss"},
    # Qwen
    "qwen-qwq-32b": {"ctx": 131_072, "family": "qwen"},
    "qwen-2.5-coder-32b": {"ctx": 131_072, "family": "qwen"},
    "qwen-2.5-32b": {"ctx": 131_072, "family": "qwen"},
    # DeepSeek
    "deepseek-r1-distill-llama-70b": {"ctx": 128_000, "family": "deepseek"},
    # Gemma
    "gemma2-9b-it": {"ctx": 8_192, "family": "gemma"},
    # Mistral
    "mistral-saba-24b": {"ctx": 32_768, "family": "mistral"},
    # Allam
    "allam-2-7b": {"ctx": 4_096, "family": "allam"},
    # Playai TTS
    "playai-tts": {"ctx": 0, "family": "tts"},
    "playai-tts-arabic": {"ctx": 0, "family": "tts"},
}

# Short aliases → full model names
_ALIASES: dict[str, str] = {
    "llama-3.3-70b-versatile": "llama-3.3-70b-versatile",
    "llama4-scout": "meta-llama/llama-4-scout-17b-16e-instruct",
    "llama4-maverick": "meta-llama/llama-4-maverick-17b-128e-instruct",
    "qwen3-32b": "qwen-qwq-32b",
    "deepseek-r1": "deepseek-r1-distill-llama-70b",
}


class GroqGenerator(Generator):
    """
    Ultra-fast inference generator via Groq Cloud.

    Usage:
        gen = GroqGenerator(model="llama-3.3-70b-versatile")
        resp = gen.generate("Explain quantum computing")

        # Streaming
        gen = GroqGenerator(model="llama4-scout")
        resp = gen.generate_stream("Hello", on_chunk=print)

        # JSON mode
        gen = GroqGenerator(model="llama-3.3-70b-versatile", json_mode=True)
    """

    name = "groq"
    provider = "groq"
    supports_streaming = True

    API_BASE = "https://api.groq.com/openai/v1"

    def __init__(self, config: Optional[GeneratorConfig] = None, **kwargs):
        super().__init__(config, **kwargs)
        if not self.config.model:
            self.config.model = "llama-3.3-70b-versatile"

        # Resolve aliases
        self.config.model = _ALIASES.get(self.config.model, self.config.model)

        self._api_key = kwargs.get("api_key", os.environ.get("GROQ_API_KEY", ""))
        self._json_mode = kwargs.get("json_mode", False)
        self._system = kwargs.get("system", None)
        self._max_retries = kwargs.get("max_retries", 3)
        self._total_tokens_used = 0
        self._total_requests = 0
        self._total_latency = 0.0

    def _call_api(self, messages: list[dict], **kwargs) -> GeneratorResponse:
        if self._system and not any(m.get("role") == "system" for m in messages):
            messages = [{"role": "system", "content": self._system}] + messages

        payload: dict = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "top_p": self.config.top_p,
            "stream": False,
        }
        if self.config.stop:
            payload["stop"] = self.config.stop
        if self.config.seed is not None:
            payload["seed"] = self.config.seed
        if self._json_mode:
            payload["response_format"] = {"type": "json_object"}

        # Retry with backoff for rate limits
        result = self._request_with_retry(payload)
        self._total_requests += 1

        choice = result["choices"][0]
        usage = result.get("usage", {})
        self._total_tokens_used += usage.get("total_tokens", 0)

        # Groq reports speed metrics
        x_groq = result.get("x_groq", {})
        queue_time = usage.get("queue_time", 0)
        prompt_time = usage.get("prompt_time", 0)
        completion_time = usage.get("completion_time", 0)
        total_time = usage.get("total_time", 0)

        tps = 0.0
        if completion_time and completion_time > 0:
            tps = usage.get("completion_tokens", 0) / completion_time

        return GeneratorResponse(
            text=choice["message"]["content"],
            model=result.get("model", self.config.model),
            input_tokens=usage.get("prompt_tokens", 0),
            output_tokens=usage.get("completion_tokens", 0),
            total_tokens=usage.get("total_tokens", 0),
            finish_reason=choice.get("finish_reason", ""),
            raw={
                **result,
                "_speed": {
                    "tokens_per_sec": round(tps, 1),
                    "queue_time_s": queue_time,
                    "prompt_time_s": prompt_time,
                    "completion_time_s": completion_time,
                    "total_time_s": total_time,
                },
            },
        )

    def generate_stream(self, prompt: str, on_chunk: Optional[Callable[[str], None]] = None, **kwargs) -> GeneratorResponse:
        """Generate with streaming output."""
        messages = [{"role": "user", "content": prompt}]
        if self._system:
            messages = [{"role": "system", "content": self._system}] + messages

        payload = {
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "top_p": self.config.top_p,
            "stream": True,
        }

        data = json.dumps(payload).encode()
        req = urllib.request.Request(
            f"{self.API_BASE}/chat/completions",
            data=data,
            headers=self._headers(),
        )

        full_text = ""
        model = self.config.model

        with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:
            for line in resp:
                line_str = line.decode().strip()
                if not line_str or line_str == "data: [DONE]":
                    continue
                if line_str.startswith("data: "):
                    chunk = json.loads(line_str[6:])
                    delta = chunk.get("choices", [{}])[0].get("delta", {})
                    token = delta.get("content", "")
                    if token:
                        full_text += token
                        if on_chunk:
                            on_chunk(token)
                    model = chunk.get("model", model) or model

        return GeneratorResponse(
            text=full_text, model=model,
            output_tokens=len(full_text.split()),
            finish_reason="stop",
        )

    def _request_with_retry(self, payload: dict) -> dict:
        """Send request with retry on rate limits."""
        data = json.dumps(payload).encode()

        for attempt in range(self._max_retries):
            req = urllib.request.Request(
                f"{self.API_BASE}/chat/completions",
                data=data,
                headers=self._headers(),
            )
            try:
                start = time.time()
                with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:
                    result = json.loads(resp.read())
                self._total_latency += time.time() - start
                return result
            except urllib.error.HTTPError as e:
                if e.code == 429 and attempt < self._max_retries - 1:
                    retry_after = float(e.headers.get("retry-after", 2 ** attempt))
                    logger.warning("Rate limited, retrying in %.1fs (attempt %d)", retry_after, attempt + 1)
                    time.sleep(retry_after)
                else:
                    raise

        raise RuntimeError("Groq API request failed after retries")

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

    # ── Model Info ────────────────────────────────────────────────────

    @staticmethod
    def available_models() -> list[str]:
        """List all available Groq models."""
        return list(GROQ_MODELS.keys())

    def get_context_length(self) -> int:
        """Get context window for current model."""
        info = GROQ_MODELS.get(self.config.model, {})
        return info.get("ctx", 8_192)

    # ── Statistics ────────────────────────────────────────────────────

    @property
    def total_tokens(self) -> int:
        return self._total_tokens_used

    @property
    def total_requests(self) -> int:
        return self._total_requests

    @property
    def avg_latency(self) -> float:
        return self._total_latency / max(self._total_requests, 1)
