"""Provider abstraction layer for LLM integrations."""

from __future__ import annotations

import json
import logging
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)


@dataclass
class ProviderResponse:
    output: str = ""
    raw: dict = field(default_factory=dict)
    model: str = ""
    usage: dict = field(default_factory=dict)
    latency_ms: float = 0.0
    error: Optional[str] = None
    tool_calls: list[dict] = field(default_factory=list)


class BaseProvider(ABC):
    """Abstract LLM provider."""

    name: str = "base"

    @abstractmethod
    def call(self, prompt: str, **kwargs: Any) -> ProviderResponse:
        ...

    @abstractmethod
    def call_chat(self, messages: list[dict], **kwargs: Any) -> ProviderResponse:
        ...


class OpenAIProvider(BaseProvider):
    name = "openai"

    def __init__(self, model: str = "gpt-4o", api_key: str = "", base_url: str = ""):
        self.model = model
        self.api_key = api_key or os.environ.get("OPENAI_API_KEY", "")
        self.base_url = base_url or "https://api.openai.com/v1"

    def call(self, prompt: str, **kwargs: Any) -> ProviderResponse:
        return self.call_chat([{"role": "user", "content": prompt}], **kwargs)

    def call_chat(self, messages: list[dict], **kwargs: Any) -> ProviderResponse:
        import time
        try:
            import openai
        except ImportError:
            return ProviderResponse(error="openai package not installed")
        client = openai.OpenAI(api_key=self.api_key, base_url=self.base_url)
        t0 = time.time()
        try:
            resp = client.chat.completions.create(model=self.model, messages=messages, **kwargs)
            latency = (time.time() - t0) * 1000
            choice = resp.choices[0]
            tool_calls = []
            if choice.message.tool_calls:
                for tc in choice.message.tool_calls:
                    tool_calls.append({"name": tc.function.name, "arguments": json.loads(tc.function.arguments)})
            return ProviderResponse(
                output=choice.message.content or "",
                model=resp.model,
                usage={"prompt_tokens": resp.usage.prompt_tokens, "completion_tokens": resp.usage.completion_tokens} if resp.usage else {},
                latency_ms=latency,
                tool_calls=tool_calls,
            )
        except Exception as e:
            return ProviderResponse(error=str(e), latency_ms=(time.time() - t0) * 1000)


class AnthropicProvider(BaseProvider):
    name = "anthropic"

    def __init__(self, model: str = "claude-sonnet-4-20250514", api_key: str = ""):
        self.model = model
        self.api_key = api_key or os.environ.get("ANTHROPIC_API_KEY", "")

    def call(self, prompt: str, **kwargs: Any) -> ProviderResponse:
        return self.call_chat([{"role": "user", "content": prompt}], **kwargs)

    def call_chat(self, messages: list[dict], **kwargs: Any) -> ProviderResponse:
        import time
        try:
            import anthropic
        except ImportError:
            return ProviderResponse(error="anthropic package not installed")
        client = anthropic.Anthropic(api_key=self.api_key)
        t0 = time.time()
        try:
            resp = client.messages.create(model=self.model, messages=messages, max_tokens=kwargs.get("max_tokens", 4096))
            latency = (time.time() - t0) * 1000
            output = "".join(b.text for b in resp.content if hasattr(b, "text"))
            return ProviderResponse(
                output=output, model=resp.model,
                usage={"input_tokens": resp.usage.input_tokens, "output_tokens": resp.usage.output_tokens},
                latency_ms=latency,
            )
        except Exception as e:
            return ProviderResponse(error=str(e), latency_ms=(time.time() - t0) * 1000)


class GoogleProvider(BaseProvider):
    name = "google"

    def __init__(self, model: str = "gemini-2.0-flash", api_key: str = ""):
        self.model = model
        self.api_key = api_key or os.environ.get("GOOGLE_API_KEY", "")

    def call(self, prompt: str, **kwargs: Any) -> ProviderResponse:
        return self.call_chat([{"role": "user", "content": prompt}], **kwargs)

    def call_chat(self, messages: list[dict], **kwargs: Any) -> ProviderResponse:
        import time
        try:
            import google.generativeai as genai
        except ImportError:
            return ProviderResponse(error="google-generativeai package not installed")
        genai.configure(api_key=self.api_key)
        model = genai.GenerativeModel(self.model)
        t0 = time.time()
        try:
            content = "\n".join(f"{m['role']}: {m['content']}" for m in messages)
            resp = model.generate_content(content)
            return ProviderResponse(output=resp.text, model=self.model, latency_ms=(time.time() - t0) * 1000)
        except Exception as e:
            return ProviderResponse(error=str(e), latency_ms=(time.time() - t0) * 1000)


class AzureOpenAIProvider(BaseProvider):
    name = "azure"

    def __init__(self, deployment: str = "", endpoint: str = "", api_key: str = "", api_version: str = "2024-02-15-preview"):
        self.deployment = deployment or os.environ.get("AZURE_OPENAI_DEPLOYMENT", "")
        self.endpoint = endpoint or os.environ.get("AZURE_OPENAI_ENDPOINT", "")
        self.api_key = api_key or os.environ.get("AZURE_OPENAI_API_KEY", "")
        self.api_version = api_version

    def call(self, prompt: str, **kwargs: Any) -> ProviderResponse:
        return self.call_chat([{"role": "user", "content": prompt}], **kwargs)

    def call_chat(self, messages: list[dict], **kwargs: Any) -> ProviderResponse:
        import time
        try:
            import openai
        except ImportError:
            return ProviderResponse(error="openai package not installed")
        client = openai.AzureOpenAI(azure_endpoint=self.endpoint, api_key=self.api_key, api_version=self.api_version)
        t0 = time.time()
        try:
            resp = client.chat.completions.create(model=self.deployment, messages=messages, **kwargs)
            choice = resp.choices[0]
            return ProviderResponse(output=choice.message.content or "", model=self.deployment, latency_ms=(time.time() - t0) * 1000)
        except Exception as e:
            return ProviderResponse(error=str(e), latency_ms=(time.time() - t0) * 1000)


class BedrockProvider(BaseProvider):
    name = "bedrock"

    def __init__(self, model_id: str = "anthropic.claude-3-sonnet-20240229-v1:0", region: str = "us-east-1"):
        self.model_id = model_id
        self.region = region

    def call(self, prompt: str, **kwargs: Any) -> ProviderResponse:
        return self.call_chat([{"role": "user", "content": prompt}], **kwargs)

    def call_chat(self, messages: list[dict], **kwargs: Any) -> ProviderResponse:
        import time
        try:
            import boto3
        except ImportError:
            return ProviderResponse(error="boto3 package not installed")
        client = boto3.client("bedrock-runtime", region_name=self.region)
        t0 = time.time()
        try:
            body = json.dumps({"messages": messages, "max_tokens": kwargs.get("max_tokens", 4096), "anthropic_version": "bedrock-2023-05-31"})
            resp = client.invoke_model(modelId=self.model_id, body=body, contentType="application/json")
            result = json.loads(resp["body"].read())
            output = "".join(b.get("text", "") for b in result.get("content", []))
            return ProviderResponse(output=output, model=self.model_id, latency_ms=(time.time() - t0) * 1000)
        except Exception as e:
            return ProviderResponse(error=str(e), latency_ms=(time.time() - t0) * 1000)


class OllamaProvider(BaseProvider):
    name = "ollama"

    def __init__(self, model: str = "llama3", base_url: str = "http://localhost:11434"):
        self.model = model
        self.base_url = base_url

    def call(self, prompt: str, **kwargs: Any) -> ProviderResponse:
        return self.call_chat([{"role": "user", "content": prompt}], **kwargs)

    def call_chat(self, messages: list[dict], **kwargs: Any) -> ProviderResponse:
        import time
        try:
            import httpx
        except ImportError:
            return ProviderResponse(error="httpx package not installed")
        t0 = time.time()
        try:
            resp = httpx.post(f"{self.base_url}/api/chat", json={"model": self.model, "messages": messages, "stream": False}, timeout=120)
            data = resp.json()
            return ProviderResponse(output=data.get("message", {}).get("content", ""), model=self.model, latency_ms=(time.time() - t0) * 1000)
        except Exception as e:
            return ProviderResponse(error=str(e), latency_ms=(time.time() - t0) * 1000)


class MistralProvider(BaseProvider):
    name = "mistral"

    def __init__(self, model: str = "mistral-large-latest", api_key: str = ""):
        self.model = model
        self.api_key = api_key or os.environ.get("MISTRAL_API_KEY", "")
        self.base_url = "https://api.mistral.ai/v1"

    def call(self, prompt: str, **kwargs: Any) -> ProviderResponse:
        return self.call_chat([{"role": "user", "content": prompt}], **kwargs)

    def call_chat(self, messages: list[dict], **kwargs: Any) -> ProviderResponse:
        import time
        try:
            import httpx
        except ImportError:
            return ProviderResponse(error="httpx package not installed")
        t0 = time.time()
        try:
            resp = httpx.post(
                f"{self.base_url}/chat/completions",
                json={"model": self.model, "messages": messages, **kwargs},
                headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                timeout=120,
            )
            resp.raise_for_status()
            data = resp.json()
            choice = data["choices"][0]
            return ProviderResponse(
                output=choice["message"]["content"] or "",
                model=data.get("model", self.model),
                usage=data.get("usage", {}),
                latency_ms=(time.time() - t0) * 1000,
            )
        except Exception as e:
            return ProviderResponse(error=str(e), latency_ms=(time.time() - t0) * 1000)


class DeepSeekProvider(BaseProvider):
    name = "deepseek"

    def __init__(self, model: str = "deepseek-chat", api_key: str = ""):
        self.model = model
        self.api_key = api_key or os.environ.get("DEEPSEEK_API_KEY", "")
        self.base_url = "https://api.deepseek.com/v1"

    def call(self, prompt: str, **kwargs: Any) -> ProviderResponse:
        return self.call_chat([{"role": "user", "content": prompt}], **kwargs)

    def call_chat(self, messages: list[dict], **kwargs: Any) -> ProviderResponse:
        import time
        try:
            import httpx
        except ImportError:
            return ProviderResponse(error="httpx package not installed")
        t0 = time.time()
        try:
            resp = httpx.post(
                f"{self.base_url}/chat/completions",
                json={"model": self.model, "messages": messages},
                headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                timeout=120,
            )
            resp.raise_for_status()
            data = resp.json()
            choice = data["choices"][0]
            return ProviderResponse(
                output=choice["message"]["content"] or "",
                model=data.get("model", self.model),
                usage=data.get("usage", {}),
                latency_ms=(time.time() - t0) * 1000,
            )
        except Exception as e:
            return ProviderResponse(error=str(e), latency_ms=(time.time() - t0) * 1000)


class xAIProvider(BaseProvider):
    """xAI Grok provider (OpenAI-compatible API)."""
    name = "xai"

    def __init__(self, model: str = "grok-3", api_key: str = ""):
        self.model = model
        self.api_key = api_key or os.environ.get("XAI_API_KEY", "")
        self.base_url = "https://api.x.ai/v1"

    def call(self, prompt: str, **kwargs: Any) -> ProviderResponse:
        return self.call_chat([{"role": "user", "content": prompt}], **kwargs)

    def call_chat(self, messages: list[dict], **kwargs: Any) -> ProviderResponse:
        import time
        try:
            import openai
        except ImportError:
            return ProviderResponse(error="openai package not installed")
        client = openai.OpenAI(api_key=self.api_key, base_url=self.base_url)
        t0 = time.time()
        try:
            resp = client.chat.completions.create(model=self.model, messages=messages, **kwargs)
            choice = resp.choices[0]
            return ProviderResponse(
                output=choice.message.content or "",
                model=resp.model,
                usage={"prompt_tokens": resp.usage.prompt_tokens, "completion_tokens": resp.usage.completion_tokens} if resp.usage else {},
                latency_ms=(time.time() - t0) * 1000,
            )
        except Exception as e:
            return ProviderResponse(error=str(e), latency_ms=(time.time() - t0) * 1000)


class CohereProvider(BaseProvider):
    name = "cohere"

    def __init__(self, model: str = "command-r-plus", api_key: str = ""):
        self.model = model
        self.api_key = api_key or os.environ.get("COHERE_API_KEY", "")

    def call(self, prompt: str, **kwargs: Any) -> ProviderResponse:
        return self.call_chat([{"role": "user", "content": prompt}], **kwargs)

    def call_chat(self, messages: list[dict], **kwargs: Any) -> ProviderResponse:
        import time
        try:
            import httpx
        except ImportError:
            return ProviderResponse(error="httpx package not installed")
        t0 = time.time()
        try:
            # Convert to Cohere chat history format
            chat_history = []
            message = ""
            for m in messages:
                role = m.get("role", "user")
                content = m.get("content", "")
                if role == "user":
                    message = content
                elif role == "assistant":
                    chat_history.append({"role": "CHATBOT", "message": content})
                elif role == "system":
                    chat_history.insert(0, {"role": "SYSTEM", "message": content})
            resp = httpx.post(
                "https://api.cohere.ai/v1/chat",
                json={"model": self.model, "message": message, "chat_history": chat_history},
                headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                timeout=120,
            )
            resp.raise_for_status()
            data = resp.json()
            return ProviderResponse(
                output=data.get("text", ""),
                model=self.model,
                usage=data.get("meta", {}).get("billed_units", {}),
                latency_ms=(time.time() - t0) * 1000,
            )
        except Exception as e:
            return ProviderResponse(error=str(e), latency_ms=(time.time() - t0) * 1000)


class PerplexityProvider(BaseProvider):
    """Perplexity sonar provider (OpenAI-compatible API)."""
    name = "perplexity"

    def __init__(self, model: str = "sonar-pro", api_key: str = ""):
        self.model = model
        self.api_key = api_key or os.environ.get("PERPLEXITY_API_KEY", "")
        self.base_url = "https://api.perplexity.ai"

    def call(self, prompt: str, **kwargs: Any) -> ProviderResponse:
        return self.call_chat([{"role": "user", "content": prompt}], **kwargs)

    def call_chat(self, messages: list[dict], **kwargs: Any) -> ProviderResponse:
        import time
        try:
            import httpx
        except ImportError:
            return ProviderResponse(error="httpx package not installed")
        t0 = time.time()
        try:
            resp = httpx.post(
                f"{self.base_url}/chat/completions",
                json={"model": self.model, "messages": messages},
                headers={"Authorization": f"Bearer {self.api_key}", "Content-Type": "application/json"},
                timeout=120,
            )
            resp.raise_for_status()
            data = resp.json()
            choice = data["choices"][0]
            return ProviderResponse(
                output=choice["message"]["content"] or "",
                model=data.get("model", self.model),
                usage=data.get("usage", {}),
                latency_ms=(time.time() - t0) * 1000,
            )
        except Exception as e:
            return ProviderResponse(error=str(e), latency_ms=(time.time() - t0) * 1000)


class ReplicateProvider(BaseProvider):
    name = "replicate"

    def __init__(self, model: str = "meta/llama-3-8b-instruct", api_key: str = ""):
        self.model = model
        self.api_key = api_key or os.environ.get("REPLICATE_API_TOKEN", "")

    def call(self, prompt: str, **kwargs: Any) -> ProviderResponse:
        return self.call_chat([{"role": "user", "content": prompt}], **kwargs)

    def call_chat(self, messages: list[dict], **kwargs: Any) -> ProviderResponse:
        import time
        try:
            import httpx
        except ImportError:
            return ProviderResponse(error="httpx package not installed")
        t0 = time.time()
        try:
            prompt_text = "\n".join(f"{m['role']}: {m['content']}" for m in messages)
            resp = httpx.post(
                f"https://api.replicate.com/v1/models/{self.model}/predictions",
                json={"input": {"prompt": prompt_text, "max_new_tokens": kwargs.get("max_tokens", 512)}},
                headers={"Authorization": f"Token {self.api_key}", "Content-Type": "application/json"},
                timeout=120,
            )
            resp.raise_for_status()
            data = resp.json()
            output = data.get("output", "")
            if isinstance(output, list):
                output = "".join(output)
            return ProviderResponse(output=output, model=self.model, latency_ms=(time.time() - t0) * 1000)
        except Exception as e:
            return ProviderResponse(error=str(e), latency_ms=(time.time() - t0) * 1000)


class SimulatedUserProvider(BaseProvider):
    """Simulates a user for automated red team testing."""
    name = "simulated_user"

    def __init__(self, persona: str = "helpful user", provider: BaseProvider | None = None):
        self.persona = persona
        self.provider = provider

    def call(self, prompt: str, **kwargs: Any) -> ProviderResponse:
        system_msg = f"You are simulating a {self.persona}. Respond naturally as this persona would."
        return self.call_chat([{"role": "system", "content": system_msg}, {"role": "user", "content": prompt}], **kwargs)

    def call_chat(self, messages: list[dict], **kwargs: Any) -> ProviderResponse:
        if self.provider:
            return self.provider.call_chat(messages, **kwargs)
        return ProviderResponse(output=f"[Simulated {self.persona} response to: {messages[-1].get('content', '')[:100]}]")


# ── Registry ──

_PROVIDERS: dict[str, type[BaseProvider]] = {
    "openai": OpenAIProvider,
    "anthropic": AnthropicProvider,
    "google": GoogleProvider,
    "azure": AzureOpenAIProvider,
    "bedrock": BedrockProvider,
    "ollama": OllamaProvider,
    "mistral": MistralProvider,
    "deepseek": DeepSeekProvider,
    "xai": xAIProvider,
    "cohere": CohereProvider,
    "perplexity": PerplexityProvider,
    "replicate": ReplicateProvider,
    "simulated_user": SimulatedUserProvider,
}


def get_provider(name: str, **kwargs: Any) -> BaseProvider:
    cls = _PROVIDERS.get(name)
    if not cls:
        raise ValueError(f"Unknown provider: {name}. Available: {list(_PROVIDERS.keys())}")
    return cls(**kwargs)


def register_provider(name: str, cls: type[BaseProvider]) -> None:
    _PROVIDERS[name] = cls


def list_providers() -> list[str]:
    return list(_PROVIDERS.keys())
