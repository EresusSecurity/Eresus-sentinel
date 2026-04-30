"""
OpenAI Generator — GPT-5.4, GPT-5.3-Codex, GPT-OSS, o3/o4-mini.

Production-grade features:
  - Full GPT-5.4 series (March 2026): flagship, pro, mini, nano
  - GPT-5.3-Codex (coding), GPT-OSS open-weight
  - o3/o4-mini reasoning models with max_completion_tokens
  - Streaming with chunk callbacks
  - JSON mode / structured output
  - Vision/multimodal support
  - Tool/function calling
  - Organization and project routing
  - Azure OpenAI endpoint support
  - Response format enforcement
  - Model context length lookup

Env: OPENAI_API_KEY, OPENAI_ORG_ID
"""

from __future__ import annotations

import logging
import os
from typing import Callable, Optional

from sentinel.redteam.generators.base import Generator, GeneratorConfig, GeneratorResponse

logger = logging.getLogger(__name__)

CONTEXT_LENGTHS = {
    # GPT-5.4 series (March 2026) — 1M context window
    "gpt-5.4": 1_050_000, "gpt-5.4-pro": 1_050_000,
    "gpt-5.4-mini": 1_050_000, "gpt-5.4-nano": 1_050_000,
    # GPT-5.3 Codex (Feb 2026)
    "gpt-5.3-codex": 512_000,
    # GPT-5.2 (Dec 2025)
    "gpt-5.2": 256_000,
    # GPT-OSS open-weight (Aug 2025)
    "gpt-oss-120b": 128_000, "gpt-oss-20b": 128_000,
    # Legacy models (still available)
    "gpt-4o": 128_000, "gpt-4o-mini": 128_000,
    "gpt-4-turbo": 128_000, "gpt-4": 8_192,
    # Reasoning models
    "o4-mini": 200_000, "o3": 200_000, "o3-mini": 200_000,
    "o1": 200_000, "o1-mini": 128_000,
}

REASONING_MODELS = {"o4-mini", "o3", "o3-mini", "o1", "o1-mini", "o1-preview"}

# Short aliases
_ALIASES: dict[str, str] = {
    "gpt5": "gpt-5.4",
    "gpt5-mini": "gpt-5.4-mini",
    "codex": "gpt-5.3-codex",
    "4o": "gpt-4o",
    "4o-mini": "gpt-4o-mini",
}


class OpenAIGenerator(Generator):
    """
    OpenAI API generator with full model coverage (April 2026).

    Usage:
        gen = OpenAIGenerator(model="gpt-5.4-mini")
        resp = gen.generate("Hello, how are you?")

        # Reasoning model
        gen = OpenAIGenerator(model="o3")

        # JSON mode
        resp = gen.generate("List 3 colors", json_mode=True)

        # Streaming
        resp = gen.generate_stream("Hello", on_chunk=print)

        # Vision
        gen = OpenAIGenerator(model="gpt-5.4-mini")
        resp = gen.generate_vision("What's in this image?", image_url="...")

        # Azure OpenAI
        gen = OpenAIGenerator(model="my-deployment", base_url="https://my.openai.azure.com/...")
    """

    name = "openai"
    provider = "openai"
    supports_streaming = True

    def __init__(self, config: Optional[GeneratorConfig] = None, **kwargs):
        super().__init__(config, **kwargs)
        if not self.config.model:
            self.config.model = "gpt-5.4-mini"

        # Resolve aliases
        self.config.model = _ALIASES.get(self.config.model, self.config.model)

        self._api_key = kwargs.get("api_key", os.environ.get("OPENAI_API_KEY", ""))
        self._base_url = kwargs.get("base_url", None)
        self._org_id = kwargs.get("organization", os.environ.get("OPENAI_ORG_ID"))
        self._json_mode = kwargs.get("json_mode", False)
        self._client = None
        self._total_cost = 0.0

    @property
    def client(self):
        if self._client is None:
            import openai
            kw = {"api_key": self._api_key}
            if self._base_url:
                kw["base_url"] = self._base_url
            if self._org_id:
                kw["organization"] = self._org_id
            self._client = openai.OpenAI(**kw)
        return self._client

    def _call_api(self, messages: list[dict], **kwargs) -> GeneratorResponse:
        is_reasoning = self.config.model in REASONING_MODELS
        json_mode = kwargs.pop("json_mode", self._json_mode)

        create_args = {
            "model": self.config.model,
            "messages": messages,
        }

        if is_reasoning:
            # Reasoning models: no temperature, no top_p
            if self.config.max_tokens:
                create_args["max_completion_tokens"] = self.config.max_tokens
        else:
            create_args["temperature"] = self.config.temperature
            create_args["max_tokens"] = self.config.max_tokens
            create_args["top_p"] = self.config.top_p
            if self.config.frequency_penalty:
                create_args["frequency_penalty"] = self.config.frequency_penalty
            if self.config.presence_penalty:
                create_args["presence_penalty"] = self.config.presence_penalty
            if self.config.stop:
                create_args["stop"] = self.config.stop
            if self.config.seed is not None:
                create_args["seed"] = self.config.seed

        # JSON mode
        if json_mode and not is_reasoning:
            create_args["response_format"] = {"type": "json_object"}

        # Tools/functions
        tools = kwargs.pop("tools", None)
        if tools:
            create_args["tools"] = tools

        response = self.client.chat.completions.create(**create_args)
        choice = response.choices[0]

        # Handle tool calls
        text = choice.message.content or ""
        tool_calls = None
        if hasattr(choice.message, "tool_calls") and choice.message.tool_calls:
            tool_calls = [
                {
                    "id": tc.id,
                    "type": tc.type,
                    "function": {
                        "name": tc.function.name,
                        "arguments": tc.function.arguments,
                    },
                }
                for tc in choice.message.tool_calls
            ]

        return GeneratorResponse(
            text=text,
            model=response.model,
            input_tokens=response.usage.prompt_tokens if response.usage else 0,
            output_tokens=response.usage.completion_tokens if response.usage else 0,
            total_tokens=response.usage.total_tokens if response.usage else 0,
            finish_reason=choice.finish_reason or "",
            raw={
                "response": response,
                "tool_calls": tool_calls,
                "system_fingerprint": getattr(response, "system_fingerprint", ""),
            },
        )

    def generate_stream(self, prompt: str, on_chunk: Optional[Callable[[str], None]] = None, **kwargs) -> GeneratorResponse:
        """Generate with streaming output."""
        messages = [{"role": "user", "content": prompt}]
        if self.config.system_prompt:
            messages = [{"role": "system", "content": self.config.system_prompt}] + messages

        create_args = {
            "model": self.config.model,
            "messages": messages,
            "stream": True,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }

        full_text = ""
        model = self.config.model

        stream = self.client.chat.completions.create(**create_args)
        for chunk in stream:
            if chunk.choices and chunk.choices[0].delta.content:
                token = chunk.choices[0].delta.content
                full_text += token
                if on_chunk:
                    on_chunk(token)
            model = chunk.model or model

        return GeneratorResponse(
            text=full_text,
            model=model,
            output_tokens=len(full_text.split()),
            finish_reason="stop",
        )

    def generate_vision(self, prompt: str, image_url: str, **kwargs) -> GeneratorResponse:
        """Generate with vision/image input."""
        messages = [{
            "role": "user",
            "content": [
                {"type": "text", "text": prompt},
                {"type": "image_url", "image_url": {"url": image_url}},
            ],
        }]
        return self._execute(messages)

    def generate_with_tools(self, prompt: str, tools: list[dict], **kwargs) -> GeneratorResponse:
        """Generate with function/tool calling."""
        messages = [{"role": "user", "content": prompt}]
        if self.config.system_prompt:
            messages = [{"role": "system", "content": self.config.system_prompt}] + messages
        return self._execute(messages, tools=tools)

    # ── Model Info ────────────────────────────────────────────────────

    @staticmethod
    def available_models() -> list[str]:
        """List all available models."""
        return list(CONTEXT_LENGTHS.keys())

    @property
    def context_length(self) -> int:
        return CONTEXT_LENGTHS.get(self.config.model, 128_000)

    @property
    def is_reasoning_model(self) -> bool:
        return self.config.model in REASONING_MODELS
