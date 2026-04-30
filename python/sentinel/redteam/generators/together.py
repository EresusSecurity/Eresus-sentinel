"""
Together AI Generator — open-source model hosting with premium inference.

Production-grade features:
  - 30+ supported models (DeepSeek-V3.1, Qwen3.5, Llama 4, etc.)
  - Model context window tracking
  - Streaming support
  - Rate limit handling with retry
  - JSON mode support
  - System prompt injection
  - Custom sampling parameters (repetition_penalty, top_k)
  - Cost estimation based on per-model pricing
  - Usage statistics

Env: TOGETHER_API_KEY
"""

from __future__ import annotations

import json
import logging
import os
import time
import urllib.error
import urllib.request
from typing import Callable, Optional

from sentinel.redteam.generators.base import Generator, GeneratorConfig, GeneratorResponse

logger = logging.getLogger(__name__)

# Together AI popular models + context windows (April 2026)
TOGETHER_MODELS: dict[str, dict] = {
    # DeepSeek
    "deepseek-ai/DeepSeek-V3.1": {"ctx": 164_000, "price_in": 0.80, "price_out": 2.00},
    "deepseek-ai/DeepSeek-R1": {"ctx": 164_000, "price_in": 3.00, "price_out": 7.00},
    "deepseek-ai/DeepSeek-R1-Distill-Llama-70B": {"ctx": 128_000, "price_in": 0.55, "price_out": 0.55},
    # Qwen
    "Qwen/Qwen3.5-397B-Instruct": {"ctx": 131_072, "price_in": 2.50, "price_out": 7.50},
    "Qwen/Qwen2.5-72B-Instruct-Turbo": {"ctx": 131_072, "price_in": 0.60, "price_out": 0.60},
    "Qwen/Qwen2.5-Coder-32B-Instruct": {"ctx": 131_072, "price_in": 0.30, "price_out": 0.30},
    "Qwen/QwQ-32B": {"ctx": 131_072, "price_in": 0.30, "price_out": 0.30},
    # Meta Llama
    "meta-llama/Llama-4-Scout-17B-16E-Instruct": {"ctx": 512_000, "price_in": 0.18, "price_out": 0.40},
    "meta-llama/Llama-4-Maverick-17B-128E-Instruct": {"ctx": 1_048_576, "price_in": 0.27, "price_out": 0.85},
    "meta-llama/Llama-3.3-70B-Instruct-Turbo": {"ctx": 128_000, "price_in": 0.55, "price_out": 0.55},
    "meta-llama/Meta-Llama-3.1-8B-Instruct-Turbo": {"ctx": 128_000, "price_in": 0.10, "price_out": 0.10},
    "meta-llama/Meta-Llama-3.1-405B-Instruct-Turbo": {"ctx": 128_000, "price_in": 3.50, "price_out": 3.50},
    # Google
    "google/gemma-2-27b-it": {"ctx": 8_192, "price_in": 0.40, "price_out": 0.40},
    "google/gemma-2-9b-it": {"ctx": 8_192, "price_in": 0.15, "price_out": 0.15},
    # Mistral
    "mistralai/Mixtral-8x22B-Instruct-v0.1": {"ctx": 65_536, "price_in": 0.60, "price_out": 0.60},
    "mistralai/Mistral-Small-24B-Instruct-2501": {"ctx": 32_768, "price_in": 0.30, "price_out": 0.30},
    # Nvidia
    "nvidia/Llama-3.1-Nemotron-70B-Instruct-HF": {"ctx": 128_000, "price_in": 0.55, "price_out": 0.55},
    # Microsoft
    "microsoft/phi-4": {"ctx": 16_384, "price_in": 0.06, "price_out": 0.06},
}

# Short aliases
_ALIASES: dict[str, str] = {
    "deepseek-v3.1": "deepseek-ai/DeepSeek-V3.1",
    "deepseek-r1": "deepseek-ai/DeepSeek-R1",
    "qwen3.5": "Qwen/Qwen3.5-397B-Instruct",
    "qwen2.5-72b": "Qwen/Qwen2.5-72B-Instruct-Turbo",
    "llama4-scout": "meta-llama/Llama-4-Scout-17B-16E-Instruct",
    "llama4-maverick": "meta-llama/Llama-4-Maverick-17B-128E-Instruct",
    "llama-3.3-70b": "meta-llama/Llama-3.3-70B-Instruct-Turbo",
    "llama-405b": "meta-llama/Meta-Llama-3.1-405B-Instruct-Turbo",
    "phi-4": "microsoft/phi-4",
}


class TogetherGenerator(Generator):
    """
    Together AI generator — high-performance open-source model hosting.

    Usage:
        gen = TogetherGenerator(model="deepseek-v3.1")
        resp = gen.generate("Explain quantum computing")

        # Use alias
        gen = TogetherGenerator(model="qwen3.5")

        # JSON mode
        gen = TogetherGenerator(model="llama-3.3-70b", json_mode=True)

        # Streaming
        gen = TogetherGenerator(model="deepseek-r1")
        resp = gen.generate_stream("Hello", on_chunk=print)
    """

    name = "together"
    provider = "together"
    supports_streaming = True

    API_BASE = "https://api.together.xyz/v1"

    def __init__(self, config: Optional[GeneratorConfig] = None, **kwargs):
        super().__init__(config, **kwargs)
        if not self.config.model:
            self.config.model = "deepseek-ai/DeepSeek-V3.1"

        # Resolve aliases
        self.config.model = _ALIASES.get(self.config.model.lower(), self.config.model)

        self._api_key = kwargs.get("api_key", os.environ.get("TOGETHER_API_KEY", ""))
        self._json_mode = kwargs.get("json_mode", False)
        self._system = kwargs.get("system", None)
        self._repetition_penalty = kwargs.get("repetition_penalty", 1.0)
        self._top_k = kwargs.get("top_k", None)
        self._max_retries = kwargs.get("max_retries", 3)
        self._total_cost: float = 0.0
        self._total_tokens_used: int = 0
        self._total_requests: int = 0

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
            "repetition_penalty": self._repetition_penalty,
        }
        if self.config.stop:
            payload["stop"] = self.config.stop
        if self.config.seed is not None:
            payload["seed"] = self.config.seed
        if self._json_mode:
            payload["response_format"] = {"type": "json_object"}
        if self._top_k is not None:
            payload["top_k"] = self._top_k

        result = self._request_with_retry("/chat/completions", payload)
        self._total_requests += 1

        choice = result["choices"][0]
        usage = result.get("usage", {})
        input_tokens = usage.get("prompt_tokens", 0)
        output_tokens = usage.get("completion_tokens", 0)
        total_tokens = usage.get("total_tokens", 0)
        self._total_tokens_used += total_tokens

        # Cost estimation
        model_info = TOGETHER_MODELS.get(self.config.model, {})
        cost = 0.0
        if model_info:
            cost = (input_tokens * model_info.get("price_in", 0) +
                    output_tokens * model_info.get("price_out", 0)) / 1_000_000
            self._total_cost += cost

        return GeneratorResponse(
            text=choice["message"]["content"],
            model=result.get("model", self.config.model),
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=total_tokens,
            finish_reason=choice.get("finish_reason", ""),
            raw={
                **result,
                "_cost": round(cost, 6),
                "_model_info": model_info,
            },
        )

    def generate_stream(self, prompt: str, on_chunk: Optional[Callable[[str], None]] = None, **kwargs) -> GeneratorResponse:
        """Generate with streaming."""
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
                    try:
                        chunk = json.loads(line_str[6:])
                        delta = chunk.get("choices", [{}])[0].get("delta", {})
                        token = delta.get("content", "")
                        if token:
                            full_text += token
                            if on_chunk:
                                on_chunk(token)
                        model = chunk.get("model", model) or model
                    except json.JSONDecodeError:
                        pass

        return GeneratorResponse(
            text=full_text, model=model,
            output_tokens=len(full_text.split()),
            finish_reason="stop",
        )

    def _request_with_retry(self, path: str, payload: dict) -> dict:
        """Send request with rate limit retry."""
        data = json.dumps(payload).encode()

        for attempt in range(self._max_retries):
            req = urllib.request.Request(
                f"{self.API_BASE}{path}",
                data=data,
                headers=self._headers(),
            )
            try:
                with urllib.request.urlopen(req, timeout=self.config.timeout) as resp:
                    return json.loads(resp.read())
            except urllib.error.HTTPError as e:
                if e.code == 429 and attempt < self._max_retries - 1:
                    wait = 2 ** attempt
                    logger.warning("Rate limited, retrying in %ds (attempt %d)", wait, attempt + 1)
                    time.sleep(wait)
                else:
                    raise

        raise RuntimeError("Together API request failed after retries")

    def _headers(self) -> dict:
        return {
            "Authorization": f"Bearer {self._api_key}",
            "Content-Type": "application/json",
        }

    # ── Model Info ────────────────────────────────────────────────────

    @staticmethod
    def available_models() -> list[str]:
        """List all available models."""
        return list(TOGETHER_MODELS.keys())

    def get_model_cost(self) -> dict:
        """Get pricing info for current model."""
        return TOGETHER_MODELS.get(self.config.model, {})

    def get_context_length(self) -> int:
        """Get context window for current model."""
        info = TOGETHER_MODELS.get(self.config.model, {})
        return info.get("ctx", 4096)

    # ── Statistics ────────────────────────────────────────────────────

    @property
    def total_cost(self) -> float:
        return round(self._total_cost, 6)

    @property
    def total_tokens(self) -> int:
        return self._total_tokens_used

    @property
    def total_requests(self) -> int:
        return self._total_requests
