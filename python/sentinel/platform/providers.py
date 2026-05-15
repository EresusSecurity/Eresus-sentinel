from __future__ import annotations

import os
import time
from dataclasses import dataclass
from typing import Any

from sentinel.platform.formats import stable_sha256


@dataclass(frozen=True)
class ProviderRequest:
    prompt: str
    variables: dict[str, Any]
    model: str | None = None
    timeout_s: float = 30.0
    metadata: dict[str, Any] | None = None


@dataclass(frozen=True)
class ProviderResponse:
    provider: str
    model: str
    output: str
    latency_ms: int
    input_tokens: int
    output_tokens: int
    cost_usd: float
    cached: bool
    metadata: dict[str, Any]


class ProviderAdapter:
    id = "provider"
    capabilities: dict[str, Any] = {}
    policy_constraints: dict[str, Any] = {}

    def validate(self, config: dict[str, Any]) -> list[str]:
        return []

    def generate(self, request: ProviderRequest, config: dict[str, Any]) -> ProviderResponse:
        raise NotImplementedError


class MockProvider(ProviderAdapter):
    id = "mock"
    capabilities = {"streaming": True, "tools": True, "offline": True}
    policy_constraints = {"network": "disabled"}

    def generate(self, request: ProviderRequest, config: dict[str, Any]) -> ProviderResponse:
        started = time.perf_counter()
        expected = request.variables.get("expected_output")
        suffix = stable_sha256({"prompt": request.prompt, "variables": request.variables})[:12]
        output = str(expected) if expected is not None else f"{request.prompt}\n[result:{suffix}]"
        latency = int((time.perf_counter() - started) * 1000)
        return ProviderResponse(self.id, request.model or config.get("model") or "deterministic-mock", output, latency, len(request.prompt.split()), len(output.split()), 0.0, False, {"deterministic": True})


class ConfiguredHttpProvider(ProviderAdapter):
    id = "custom-http"
    capabilities = {"streaming": False, "tools": False, "offline": False}
    policy_constraints = {"requires_explicit_enable": True}

    def validate(self, config: dict[str, Any]) -> list[str]:
        if not config.get("url"):
            return ["url is required"]
        if not config.get("allow_live"):
            return ["allow_live must be true for network providers"]
        return []

    def generate(self, request: ProviderRequest, config: dict[str, Any]) -> ProviderResponse:
        errors = self.validate(config)
        if errors:
            raise ValueError("; ".join(errors))
        raise RuntimeError("network provider transport is not enabled in deterministic core")


class OfflineNamedProvider(ProviderAdapter):
    capabilities = {"streaming": False, "tools": False, "offline": False}
    policy_constraints = {"requires_explicit_enable": True, "default": "offline"}

    def __init__(self, provider_id: str, env_names: tuple[str, ...]) -> None:
        self.id = provider_id
        self.env_names = env_names

    def validate(self, config: dict[str, Any]) -> list[str]:
        missing = [name for name in self.env_names if not os.environ.get(name) and not config.get("credentials", {}).get(name)]
        if not config.get("allow_live"):
            return ["allow_live must be true"]
        if missing:
            return [f"missing credential {missing[0]}"]
        return []

    def generate(self, request: ProviderRequest, config: dict[str, Any]) -> ProviderResponse:
        errors = self.validate(config)
        if errors:
            raise ValueError("; ".join(errors))
        raise RuntimeError("live provider transport is not enabled in deterministic core")


class ProviderRegistry:
    def __init__(self) -> None:
        self.adapters: dict[str, ProviderAdapter] = {"mock": MockProvider(), "custom-http": ConfiguredHttpProvider()}
        for provider_id, env_names in {
            "openai": ("OPENAI_API_KEY",),
            "anthropic": ("ANTHROPIC_API_KEY",),
            "google": ("GOOGLE_API_KEY",),
            "azure-openai": ("AZURE_OPENAI_API_KEY",),
            "ollama": (),
            "openrouter": ("OPENROUTER_API_KEY",),
            "bedrock": ("AWS_ACCESS_KEY_ID",),
            "vertex": ("GOOGLE_APPLICATION_CREDENTIALS",),
            "huggingface": ("HUGGINGFACE_TOKEN",),
            "groq": ("GROQ_API_KEY",),
            "mistral": ("MISTRAL_API_KEY",),
            "cohere": ("COHERE_API_KEY",),
            "deepseek": ("DEEPSEEK_API_KEY",),
            "local-gguf": (),
            "mcp": (),
        }.items():
            self.adapters[provider_id] = OfflineNamedProvider(provider_id, env_names)

    def list(self) -> list[dict[str, Any]]:
        return [
            {"id": adapter.id, "capabilities": adapter.capabilities, "policy_constraints": adapter.policy_constraints}
            for adapter in sorted(self.adapters.values(), key=lambda item: item.id)
        ]

    def get(self, provider_id: str) -> ProviderAdapter:
        if provider_id not in self.adapters:
            raise ValueError(f"unknown provider: {provider_id}")
        return self.adapters[provider_id]

    def test(self, provider_id: str, config: dict[str, Any] | None = None) -> dict[str, Any]:
        adapter = self.get(provider_id)
        cfg = config or {}
        errors = adapter.validate(cfg)
        return {"id": provider_id, "ok": not errors, "errors": errors, "capabilities": adapter.capabilities, "policy_constraints": adapter.policy_constraints}
