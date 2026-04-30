"""
Anthropic Generator — Claude 4.6 Opus/Sonnet/Haiku.

Production-grade features:
  - Claude 4.6 series (2026): Opus, Sonnet, Haiku with 1M context
  - Extended thinking (budget_tokens control)
  - Streaming with chunk callbacks
  - Tool use / function calling
  - Vision/multimodal support
  - System prompt via dedicated parameter
  - PDF document support
  - Prompt caching
  - Token counting API
  - Model context length tracking

Env: ANTHROPIC_API_KEY
"""

from __future__ import annotations

import logging
import os
from typing import Callable, Optional

from sentinel.redteam.generators.base import Generator, GeneratorConfig, GeneratorResponse

logger = logging.getLogger(__name__)

CONTEXT_LENGTHS = {
    # Claude 4.6 series (2026) — 1M context window
    "claude-opus-4-6": 1_000_000,
    "claude-sonnet-4-6": 1_000_000,
    "claude-haiku-4-5": 1_000_000,
    # Claude 4.x (2025)
    "claude-sonnet-4-20250514": 200_000,
    "claude-opus-4-20250514": 200_000,
    # Claude 3.5 legacy
    "claude-3-5-sonnet-20241022": 200_000,
    "claude-3-5-haiku-20241022": 200_000,
    # Claude 3 legacy
    "claude-3-opus-20240229": 200_000,
}

# Short aliases
_ALIASES: dict[str, str] = {
    "opus": "claude-opus-4-6",
    "sonnet": "claude-sonnet-4-6",
    "haiku": "claude-haiku-4-5",
    "opus-4": "claude-opus-4-6",
    "sonnet-4": "claude-sonnet-4-6",
}

# Models that support extended thinking
THINKING_MODELS = {
    "claude-opus-4-6", "claude-sonnet-4-6",
    "claude-sonnet-4-20250514", "claude-opus-4-20250514",
}


class AnthropicGenerator(Generator):
    """
    Anthropic Claude generator with full 4.6 model coverage.

    Usage:
        gen = AnthropicGenerator(model="claude-sonnet-4-6")
        resp = gen.generate("Explain quantum computing")

        # Extended thinking
        resp = gen.generate("Complex problem...", extended_thinking=True, thinking_budget=20000)

        # Streaming
        resp = gen.generate_stream("Hello", on_chunk=print)

        # Vision
        resp = gen.generate_vision("What's this?", image_url="data:image/png;base64,...")

        # Tool use
        tools = [{"name": "get_weather", "description": "...", "input_schema": {...}}]
        resp = gen.generate_with_tools("What's the weather?", tools)
    """

    name = "anthropic"
    provider = "anthropic"
    supports_streaming = True

    def __init__(self, config: Optional[GeneratorConfig] = None, **kwargs):
        super().__init__(config, **kwargs)
        if not self.config.model:
            self.config.model = "claude-sonnet-4-6"

        # Resolve aliases
        self.config.model = _ALIASES.get(self.config.model, self.config.model)

        self._api_key = kwargs.get("api_key", os.environ.get("ANTHROPIC_API_KEY", ""))
        self._client = None
        self._enable_caching = kwargs.get("prompt_caching", False)

    @property
    def client(self):
        if self._client is None:
            import anthropic
            self._client = anthropic.Anthropic(api_key=self._api_key)
        return self._client

    def _call_api(self, messages: list[dict], **kwargs) -> GeneratorResponse:
        # Separate system prompt
        system_prompt = None
        filtered_messages = []
        for msg in messages:
            if msg["role"] == "system":
                system_prompt = msg["content"]
            else:
                filtered_messages.append(msg)

        create_args = {
            "model": self.config.model,
            "messages": filtered_messages,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
        }

        if system_prompt:
            if self._enable_caching:
                create_args["system"] = [
                    {"type": "text", "text": system_prompt, "cache_control": {"type": "ephemeral"}}
                ]
            else:
                create_args["system"] = system_prompt

        if self.config.top_p < 1.0:
            create_args["top_p"] = self.config.top_p
        if self.config.stop:
            create_args["stop_sequences"] = self.config.stop

        # Extended thinking
        if kwargs.get("extended_thinking") and self.config.model in THINKING_MODELS:
            create_args["thinking"] = {
                "type": "enabled",
                "budget_tokens": kwargs.get("thinking_budget", 10000),
            }
            create_args["temperature"] = 1.0

        # Tool use
        tools = kwargs.pop("tools", None)
        if tools:
            create_args["tools"] = tools

        response = self.client.messages.create(**create_args)

        # Extract text and thinking
        text = ""
        thinking_text = ""
        tool_use_blocks = []

        for block in response.content:
            if hasattr(block, "text"):
                text += block.text
            elif hasattr(block, "thinking"):
                thinking_text += block.thinking
            elif block.type == "tool_use":
                tool_use_blocks.append({
                    "id": block.id,
                    "name": block.name,
                    "input": block.input,
                })

        # Cache usage
        cache_read = getattr(response.usage, "cache_read_input_tokens", 0) or 0
        cache_create = getattr(response.usage, "cache_creation_input_tokens", 0) or 0

        return GeneratorResponse(
            text=text,
            model=response.model,
            input_tokens=response.usage.input_tokens,
            output_tokens=response.usage.output_tokens,
            total_tokens=response.usage.input_tokens + response.usage.output_tokens,
            finish_reason=response.stop_reason or "",
            raw={
                "response": response,
                "thinking": thinking_text,
                "tool_use": tool_use_blocks,
                "cache_read_tokens": cache_read,
                "cache_create_tokens": cache_create,
            },
        )

    def generate_stream(self, prompt: str, on_chunk: Optional[Callable[[str], None]] = None, **kwargs) -> GeneratorResponse:
        """Generate with streaming."""
        messages = [{"role": "user", "content": prompt}]

        create_args = {
            "model": self.config.model,
            "messages": messages,
            "max_tokens": self.config.max_tokens,
            "temperature": self.config.temperature,
        }
        if self.config.system_prompt:
            create_args["system"] = self.config.system_prompt

        full_text = ""
        input_tokens = 0
        output_tokens = 0

        with self.client.messages.stream(**create_args) as stream:
            for text in stream.text_stream:
                full_text += text
                if on_chunk:
                    on_chunk(text)
            final = stream.get_final_message()
            input_tokens = final.usage.input_tokens
            output_tokens = final.usage.output_tokens

        return GeneratorResponse(
            text=full_text,
            model=self.config.model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            total_tokens=input_tokens + output_tokens,
            finish_reason="end_turn",
        )

    def generate_vision(self, prompt: str, image_url: str, **kwargs) -> GeneratorResponse:
        """Generate with vision input (base64 or URL)."""
        # Detect if base64 or URL
        if image_url.startswith("data:"):
            media_type = image_url.split(";")[0].split(":")[1]
            data = image_url.split(",")[1]
            image_content = {
                "type": "image",
                "source": {"type": "base64", "media_type": media_type, "data": data},
            }
        else:
            image_content = {
                "type": "image",
                "source": {"type": "url", "url": image_url},
            }

        messages = [{
            "role": "user",
            "content": [
                image_content,
                {"type": "text", "text": prompt},
            ],
        }]
        return self._execute(messages)

    def generate_with_tools(self, prompt: str, tools: list[dict], **kwargs) -> GeneratorResponse:
        """Generate with tool use."""
        messages = [{"role": "user", "content": prompt}]
        return self._execute(messages, tools=tools)

    def count_tokens(self, messages: list[dict]) -> int:
        """Count tokens for a message list using Anthropic's API."""
        try:
            result = self.client.messages.count_tokens(
                model=self.config.model,
                messages=messages,
            )
            return result.input_tokens
        except Exception as e:
            logger.warning("Token counting failed: %s", e)
            return 0

    # ── Model Info ────────────────────────────────────────────────────

    @staticmethod
    def available_models() -> list[str]:
        return list(CONTEXT_LENGTHS.keys())

    @property
    def context_length(self) -> int:
        return CONTEXT_LENGTHS.get(self.config.model, 200_000)

    @property
    def supports_thinking(self) -> bool:
        return self.config.model in THINKING_MODELS
