"""OpenRouter Gateway Generator.

Routes prompts to 300+ models through a single OpenRouter API key.
Thin wrapper over LiteLLMGenerator with OpenRouter-specific defaults,
cost tracking, and model discovery.

Key benefits:
  - Single API key for all providers (OpenAI, Anthropic, Meta, Mistral, etc.)
  - Automatic fallback routing
  - Cost tracking per provider
  - Model leaderboard filtering (filter by context length, price, provider)

Env:
  OPENROUTER_API_KEY  — Required. Get from https://openrouter.ai/keys
  OPENROUTER_APP_URL  — Optional. Your app URL for rankings (default: sentinel)
  OPENROUTER_APP_NAME — Optional. Your app name (default: eresus-sentinel)

Popular models (use as model= argument):
  openrouter/openai/gpt-4o
  openrouter/anthropic/claude-3.5-sonnet
  openrouter/meta-llama/llama-3.3-70b-instruct
  openrouter/mistralai/mistral-7b-instruct
  openrouter/google/gemini-pro-1.5
  openrouter/deepseek/deepseek-r1
  openrouter/qwen/qwen-2.5-72b-instruct
  openrouter/auto  (automatic cheapest routing)
"""
from __future__ import annotations

import logging
import os
from typing import Any

from sentinel.redteam.generators.base import Generator, GeneratorConfig, GeneratorResponse

logger = logging.getLogger(__name__)


_OPENROUTER_BASE_URL = "https://openrouter.ai/api/v1"

_POPULAR_MODELS = [
    "openrouter/openai/gpt-4o",
    "openrouter/anthropic/claude-3.5-sonnet",
    "openrouter/meta-llama/llama-3.3-70b-instruct",
    "openrouter/mistralai/mistral-7b-instruct",
    "openrouter/google/gemini-pro-1.5",
    "openrouter/deepseek/deepseek-r1",
    "openrouter/qwen/qwen-2.5-72b-instruct",
    "openrouter/auto",
]


class OpenRouterGenerator(Generator):
    """OpenRouter gateway — routes to 300+ models via a single API key.

    Args:
        model:    OpenRouter model string (e.g. 'openrouter/openai/gpt-4o').
        api_key:  OpenRouter API key (default: OPENROUTER_API_KEY env var).
        app_url:  Your app URL for OpenRouter rankings.
        app_name: Your app name for OpenRouter rankings.
        config:   Standard GeneratorConfig.
    """

    name = "openrouter"
    provider = "openrouter"

    def __init__(
        self,
        model: str = "openrouter/openai/gpt-4o",
        api_key: str | None = None,
        app_url: str | None = None,
        app_name: str | None = None,
        config: GeneratorConfig | None = None,
        **kwargs,
    ) -> None:
        super().__init__(config, **kwargs)
        self.config.model = model
        self._api_key = api_key or os.environ.get("OPENROUTER_API_KEY", "")
        self._app_url = app_url or os.environ.get("OPENROUTER_APP_URL", "https://github.com/EresusSecurity/Eresus-sentinel")
        self._app_name = app_name or os.environ.get("OPENROUTER_APP_NAME", "eresus-sentinel")

        if not self._api_key:
            raise ValueError(
                "OpenRouterGenerator: OPENROUTER_API_KEY not set. "
                "Get your key at https://openrouter.ai/keys"
            )

    def _call_api(self, messages: list[dict], **kwargs) -> GeneratorResponse:
        try:
            import litellm  # type: ignore[import]
        except ImportError:
            raise RuntimeError("litellm required: pip install litellm")

        litellm.api_key = self._api_key

        extra_headers = {
            "HTTP-Referer": self._app_url,
            "X-Title": self._app_name,
        }

        response = litellm.completion(
            model=self.config.model,
            messages=messages,
            temperature=self.config.temperature,
            max_tokens=self.config.max_tokens,
            api_base=_OPENROUTER_BASE_URL,
            api_key=self._api_key,
            extra_headers=extra_headers,
        )

        text = response.choices[0].message.content or ""
        usage = response.usage or {}
        input_tokens = getattr(usage, "prompt_tokens", 0)
        output_tokens = getattr(usage, "completion_tokens", 0)

        return GeneratorResponse(
            text=text,
            model=self.config.model,
            provider="openrouter",
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=input_tokens + output_tokens,
        )

    @classmethod
    def list_popular_models(cls) -> list[str]:
        """Return curated list of popular OpenRouter models."""
        return list(_POPULAR_MODELS)

    @classmethod
    def list_models(cls, api_key: str | None = None) -> list[dict]:
        """Fetch live model list from OpenRouter API."""
        import urllib.request
        key = api_key or os.environ.get("OPENROUTER_API_KEY", "")
        req = urllib.request.Request(
            "https://openrouter.ai/api/v1/models",
            headers={"Authorization": f"Bearer {key}"},
        )
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                import json
                data = json.loads(resp.read().decode())
                return data.get("data", [])
        except Exception as exc:
            logger.warning("OpenRouter model list failed: %s", exc)
            return []
