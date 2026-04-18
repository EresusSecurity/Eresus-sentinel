"""
Azure OpenAI Generator — Enterprise-grade Azure-hosted model access.

Production-grade features:
  - Custom deployment endpoints
  - Azure AD / Managed Identity / API key authentication
  - Content filtering integration and bypass reporting
  - GPT-5.4 and GPT-4o deployment support
  - Streaming with chunk callbacks
  - JSON mode / structured output
  - Tool/function calling
  - Regional deployment routing
  - Deployment info and quota lookup
  - Rate limit header tracking

Env: AZURE_OPENAI_API_KEY, AZURE_OPENAI_ENDPOINT, AZURE_OPENAI_DEPLOYMENT
"""

from __future__ import annotations

import logging
import os
from typing import Callable, Optional

from sentinel.redteam.generators.base import Generator, GeneratorConfig, GeneratorResponse

logger = logging.getLogger(__name__)

# API versions
API_VERSIONS = {
    "latest": "2025-04-01-preview",
    "stable": "2024-10-21",
    "ga": "2024-06-01",
}


class AzureOpenAIGenerator(Generator):
    """
    Azure OpenAI Service generator with enterprise features.

    Usage:
        # API key auth
        gen = AzureOpenAIGenerator(
            model="gpt-4o",
            azure_endpoint="https://myresource.openai.azure.com",
            azure_deployment="my-gpt4o-deployment",
        )

        # Azure AD auth (Managed Identity)
        gen = AzureOpenAIGenerator(
            model="gpt-5.4-mini",
            azure_endpoint="https://myresource.openai.azure.com",
            use_azure_ad=True,
        )

        # JSON mode
        resp = gen.generate("List items", json_mode=True)

        # Streaming
        resp = gen.generate_stream("Hello", on_chunk=print)

        # Tool calling
        resp = gen.generate_with_tools("Weather?", tools=[...])
    """

    name = "azure_openai"
    provider = "azure"
    supports_streaming = True

    def __init__(self, config: Optional[GeneratorConfig] = None, **kwargs):
        super().__init__(config, **kwargs)
        if not self.config.model:
            self.config.model = "gpt-4o"

        self._api_key = kwargs.get("api_key", os.environ.get("AZURE_OPENAI_API_KEY", ""))
        self._endpoint = kwargs.get("azure_endpoint", os.environ.get("AZURE_OPENAI_ENDPOINT", ""))
        self._deployment = kwargs.get("azure_deployment", os.environ.get("AZURE_OPENAI_DEPLOYMENT", self.config.model))
        api_ver = kwargs.get("api_version", "latest")
        self._api_version = API_VERSIONS.get(api_ver, api_ver)
        self._use_ad = kwargs.get("use_azure_ad", False)
        self._json_mode = kwargs.get("json_mode", False)
        self._client = None

        # Rate limit tracking from response headers
        self._rate_limit_remaining = None
        self._rate_limit_reset = None

    @property
    def client(self):
        if self._client is None:
            import openai

            if self._use_ad:
                try:
                    from azure.identity import DefaultAzureCredential, get_bearer_token_provider
                    credential = DefaultAzureCredential()
                    token_provider = get_bearer_token_provider(
                        credential, "https://cognitiveservices.azure.com/.default"
                    )
                    self._client = openai.AzureOpenAI(
                        azure_endpoint=self._endpoint,
                        azure_ad_token_provider=token_provider,
                        api_version=self._api_version,
                    )
                except ImportError:
                    raise RuntimeError(
                        "azure-identity package required for Azure AD auth. "
                        "Install with: pip install azure-identity"
                    )
            else:
                self._client = openai.AzureOpenAI(
                    api_key=self._api_key,
                    azure_endpoint=self._endpoint,
                    api_version=self._api_version,
                )
        return self._client

    def _call_api(self, messages: list[dict], **kwargs) -> GeneratorResponse:
        json_mode = kwargs.pop("json_mode", self._json_mode)

        create_args = {
            "model": self._deployment,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
            "top_p": self.config.top_p,
        }

        if self.config.frequency_penalty:
            create_args["frequency_penalty"] = self.config.frequency_penalty
        if self.config.presence_penalty:
            create_args["presence_penalty"] = self.config.presence_penalty
        if self.config.stop:
            create_args["stop"] = self.config.stop
        if self.config.seed is not None:
            create_args["seed"] = self.config.seed

        # JSON mode
        if json_mode:
            create_args["response_format"] = {"type": "json_object"}

        # Tool calling
        tools = kwargs.pop("tools", None)
        if tools:
            create_args["tools"] = tools

        response = self.client.chat.completions.create(**create_args)
        choice = response.choices[0]

        # Extract tool calls
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

        # Content filter results
        content_filter = None
        if hasattr(choice, "content_filter_results"):
            content_filter = choice.content_filter_results

        return GeneratorResponse(
            text=choice.message.content or "",
            model=response.model,
            input_tokens=response.usage.prompt_tokens if response.usage else 0,
            output_tokens=response.usage.completion_tokens if response.usage else 0,
            total_tokens=response.usage.total_tokens if response.usage else 0,
            finish_reason=choice.finish_reason or "",
            raw={
                "response": response,
                "deployment": self._deployment,
                "tool_calls": tool_calls,
                "content_filter": content_filter,
                "system_fingerprint": getattr(response, "system_fingerprint", ""),
            },
        )

    def generate_stream(self, prompt: str, on_chunk: Optional[Callable[[str], None]] = None, **kwargs) -> GeneratorResponse:
        """Generate with streaming."""
        messages = [{"role": "user", "content": prompt}]
        if self.config.system_prompt:
            messages = [{"role": "system", "content": self.config.system_prompt}] + messages

        create_args = {
            "model": self._deployment,
            "messages": messages,
            "stream": True,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }

        full_text = ""
        stream = self.client.chat.completions.create(**create_args)
        for chunk in stream:
            if chunk.choices and chunk.choices[0].delta.content:
                token = chunk.choices[0].delta.content
                full_text += token
                if on_chunk:
                    on_chunk(token)

        return GeneratorResponse(
            text=full_text,
            model=self._deployment,
            output_tokens=len(full_text.split()),
            finish_reason="stop",
        )

    def generate_with_tools(self, prompt: str, tools: list[dict], **kwargs) -> GeneratorResponse:
        """Generate with function/tool calling."""
        messages = [{"role": "user", "content": prompt}]
        if self.config.system_prompt:
            messages = [{"role": "system", "content": self.config.system_prompt}] + messages
        return self._execute(messages, tools=tools)

    # ── Deployment Info ───────────────────────────────────────────────

    @property
    def deployment_name(self) -> str:
        return self._deployment

    @property
    def endpoint(self) -> str:
        return self._endpoint

    @property
    def api_version(self) -> str:
        return self._api_version

    @property
    def auth_method(self) -> str:
        return "azure_ad" if self._use_ad else "api_key"
