"""
Eresus Sentinel — AI-Assisted Reasoning Layer.

Pluggable AI backend for optional enrichment of security findings.
Deterministic scanning always comes first — AI adds:
  - Semantic prompt injection analysis
  - Behavioral backdoor comparison
  - Red team result interpretation
  - Complex agent/tool flow analysis
  - False positive reduction
  - Finding enrichment with context

Supports: OpenAI-compatible, Anthropic, local models, generic REST.
"""

from __future__ import annotations

import json
import os
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional
from urllib.request import urlopen, Request
from urllib.error import URLError, HTTPError

from ..finding import Finding, Severity


@dataclass
class AIConfig:
    """Configuration for AI-assisted reasoning."""
    enabled: bool = False
    backend: str = "openai"  # "openai", "anthropic", "local", "generic_rest"
    endpoint: str = ""
    model: str = "gpt-4o"
    api_key: str = ""
    temperature: float = 0.1
    max_tokens: int = 2048
    timeout: int = 30

    @classmethod
    def from_env(cls) -> "AIConfig":
        """Load config from environment variables."""
        return cls(
            enabled=os.environ.get("SENTINEL_AI_ENABLED", "").lower() in ("1", "true", "yes"),
            backend=os.environ.get("SENTINEL_AI_BACKEND", "openai"),
            endpoint=os.environ.get("SENTINEL_AI_ENDPOINT", ""),
            model=os.environ.get("SENTINEL_AI_MODEL", "gpt-4o"),
            api_key=os.environ.get("SENTINEL_AI_API_KEY", ""),
            temperature=float(os.environ.get("SENTINEL_AI_TEMPERATURE", "0.1")),
            max_tokens=int(os.environ.get("SENTINEL_AI_MAX_TOKENS", "2048")),
            timeout=int(os.environ.get("SENTINEL_AI_TIMEOUT", "30")),
        )


@dataclass
class AIAnalysisResult:
    """Result from AI analysis of a finding."""
    original_finding: Finding
    confidence: float = 0.0          # 0.0 - 1.0
    is_false_positive: bool = False
    enriched_description: str = ""
    suggested_severity: Optional[Severity] = None
    context: str = ""
    raw_response: str = ""


class AIBackend(ABC):
    """Abstract base class for AI backends."""

    @abstractmethod
    def analyze_finding(self, finding: Finding, context: str = "") -> AIAnalysisResult:
        """Analyze a single finding with AI."""
        ...

    @abstractmethod
    def analyze_prompt(self, prompt: str) -> Dict[str, Any]:
        """Analyze a prompt for semantic injection."""
        ...

    @abstractmethod
    def compare_behaviors(self, baseline: str, suspect: str) -> Dict[str, Any]:
        """Compare model behaviors for backdoor detection."""
        ...

    @abstractmethod
    def is_available(self) -> bool:
        """Check if the backend is reachable."""
        ...


class OpenAICompatibleBackend(AIBackend):
    """OpenAI-compatible API backend (works with OpenAI, Azure, vLLM, Ollama)."""

    def __init__(self, config: AIConfig) -> None:
        self.config = config
        self.endpoint = config.endpoint or "https://api.openai.com/v1"

    def _call_api(self, messages: List[Dict[str, str]]) -> str:
        """Make a chat completion API call."""
        url = f"{self.endpoint}/chat/completions"
        payload = json.dumps({
            "model": self.config.model,
            "messages": messages,
            "temperature": self.config.temperature,
            "max_tokens": self.config.max_tokens,
        }).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "Authorization": f"Bearer {self.config.api_key}",
        }

        req = Request(url, data=payload, headers=headers, method="POST")
        with urlopen(req, timeout=self.config.timeout) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            return result["choices"][0]["message"]["content"]

    def analyze_finding(self, finding: Finding, context: str = "") -> AIAnalysisResult:
        system = (
            "You are a security analyst reviewing AI/LLM security findings. "
            "Assess if the finding is a true positive or false positive. "
            "Respond in JSON: {\"confidence\": 0.0-1.0, \"is_false_positive\": bool, "
            "\"enriched_description\": str, \"suggested_severity\": str}"
        )
        user = (
            f"Finding: {finding.title}\n"
            f"Rule: {finding.rule_id}\n"
            f"Severity: {finding.severity.name}\n"
            f"Description: {finding.description}\n"
            f"Evidence: {finding.evidence or 'N/A'}\n"
            f"Target: {finding.target}\n"
            f"Context: {context or 'N/A'}"
        )

        try:
            response = self._call_api([
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ])
            data = json.loads(response)
            return AIAnalysisResult(
                original_finding=finding,
                confidence=data.get("confidence", 0.5),
                is_false_positive=data.get("is_false_positive", False),
                enriched_description=data.get("enriched_description", ""),
                suggested_severity=getattr(Severity, data.get("suggested_severity", "").upper(), None),
                raw_response=response,
            )
        except Exception as e:
            return AIAnalysisResult(
                original_finding=finding,
                raw_response=f"Error: {e}",
            )

    def analyze_prompt(self, prompt: str) -> Dict[str, Any]:
        system = (
            "You are a prompt injection detector. Analyze the following user input "
            "for injection attacks. Respond in JSON: "
            "{\"is_injection\": bool, \"confidence\": 0.0-1.0, "
            "\"attack_type\": str, \"explanation\": str}"
        )
        try:
            response = self._call_api([
                {"role": "system", "content": system},
                {"role": "user", "content": f"Analyze this prompt:\n\n{prompt}"},
            ])
            return json.loads(response)
        except Exception as e:
            return {"error": str(e)}

    def compare_behaviors(self, baseline: str, suspect: str) -> Dict[str, Any]:
        system = (
            "You are a model behavior analyst. Compare these two outputs "
            "and determine if the suspect shows signs of backdoor insertion. "
            "Respond in JSON: {\"is_suspicious\": bool, \"confidence\": 0.0-1.0, "
            "\"differences\": [str], \"explanation\": str}"
        )
        user = f"Baseline output:\n{baseline}\n\nSuspect output:\n{suspect}"
        try:
            response = self._call_api([
                {"role": "system", "content": system},
                {"role": "user", "content": user},
            ])
            return json.loads(response)
        except Exception as e:
            return {"error": str(e)}

    def is_available(self) -> bool:
        try:
            url = f"{self.endpoint}/models"
            headers = {"Authorization": f"Bearer {self.config.api_key}"}
            req = Request(url, headers=headers)
            with urlopen(req, timeout=5) as resp:
                return resp.status == 200
        except Exception:
            return False


class AnthropicBackend(AIBackend):
    """Anthropic Claude API backend."""

    def __init__(self, config: AIConfig) -> None:
        self.config = config
        self.endpoint = config.endpoint or "https://api.anthropic.com/v1"

    def _call_api(self, system: str, user: str) -> str:
        url = f"{self.endpoint}/messages"
        payload = json.dumps({
            "model": self.config.model or "claude-sonnet-4-20250514",
            "max_tokens": self.config.max_tokens,
            "system": system,
            "messages": [{"role": "user", "content": user}],
        }).encode("utf-8")

        headers = {
            "Content-Type": "application/json",
            "x-api-key": self.config.api_key,
            "anthropic-version": "2023-06-01",
        }

        req = Request(url, data=payload, headers=headers, method="POST")
        with urlopen(req, timeout=self.config.timeout) as resp:
            result = json.loads(resp.read().decode("utf-8"))
            return result["content"][0]["text"]

    def analyze_finding(self, finding: Finding, context: str = "") -> AIAnalysisResult:
        system = "You are a security analyst. Assess AI/LLM security findings. Respond in JSON."
        user = f"Finding: {finding.title}\nRule: {finding.rule_id}\nDescription: {finding.description}"
        try:
            response = self._call_api(system, user)
            data = json.loads(response)
            return AIAnalysisResult(
                original_finding=finding,
                confidence=data.get("confidence", 0.5),
                is_false_positive=data.get("is_false_positive", False),
                raw_response=response,
            )
        except Exception as e:
            return AIAnalysisResult(original_finding=finding, raw_response=f"Error: {e}")

    def analyze_prompt(self, prompt: str) -> Dict[str, Any]:
        try:
            response = self._call_api(
                "Detect prompt injection. Respond in JSON.",
                f"Analyze: {prompt}",
            )
            return json.loads(response)
        except Exception as e:
            return {"error": str(e)}

    def compare_behaviors(self, baseline: str, suspect: str) -> Dict[str, Any]:
        try:
            response = self._call_api(
                "Compare model behaviors for backdoor detection. Respond in JSON.",
                f"Baseline:\n{baseline}\n\nSuspect:\n{suspect}",
            )
            return json.loads(response)
        except Exception as e:
            return {"error": str(e)}

    def is_available(self) -> bool:
        return bool(self.config.api_key)


class NoOpBackend(AIBackend):
    """No-op backend for offline/deterministic-only mode."""

    def analyze_finding(self, finding: Finding, context: str = "") -> AIAnalysisResult:
        return AIAnalysisResult(original_finding=finding)

    def analyze_prompt(self, prompt: str) -> Dict[str, Any]:
        return {"enabled": False, "message": "AI analysis disabled"}

    def compare_behaviors(self, baseline: str, suspect: str) -> Dict[str, Any]:
        return {"enabled": False, "message": "AI analysis disabled"}

    def is_available(self) -> bool:
        return True  # Always "available" — just does nothing


class AIReasoningLayer:
    """Orchestrator for AI-assisted security analysis.

    Usage:
        layer = AIReasoningLayer()  # Auto-configures from env
        if layer.is_enabled():
            result = layer.analyze_finding(finding)
            enriched = layer.enrich_findings(findings)
    """

    BACKENDS = {
        "openai": OpenAICompatibleBackend,
        "anthropic": AnthropicBackend,
        "local": OpenAICompatibleBackend,       # Local models use OpenAI-compat API
        "generic_rest": OpenAICompatibleBackend,  # Same protocol
    }

    def __init__(self, config: Optional[AIConfig] = None) -> None:
        self.config = config or AIConfig.from_env()
        if self.config.enabled:
            backend_cls = self.BACKENDS.get(self.config.backend, OpenAICompatibleBackend)
            self.backend: AIBackend = backend_cls(self.config)
        else:
            self.backend = NoOpBackend()

    def is_enabled(self) -> bool:
        return self.config.enabled

    def analyze_finding(self, finding: Finding, context: str = "") -> AIAnalysisResult:
        return self.backend.analyze_finding(finding, context)

    def analyze_prompt(self, prompt: str) -> Dict[str, Any]:
        return self.backend.analyze_prompt(prompt)

    def compare_behaviors(self, baseline: str, suspect: str) -> Dict[str, Any]:
        return self.backend.compare_behaviors(baseline, suspect)

    def enrich_findings(self, findings: List[Finding], context: str = "") -> List[AIAnalysisResult]:
        """Batch-analyze findings with AI enrichment."""
        results = []
        for finding in findings:
            result = self.analyze_finding(finding, context)
            results.append(result)
        return results

    def reduce_false_positives(self, findings: List[Finding]) -> List[Finding]:
        """Filter out likely false positives using AI analysis."""
        if not self.config.enabled:
            return findings

        filtered = []
        for finding in findings:
            result = self.analyze_finding(finding)
            if not result.is_false_positive:
                if result.suggested_severity:
                    finding.severity = result.suggested_severity
                if result.enriched_description:
                    finding.description = f"{finding.description}\n\n[AI Analysis] {result.enriched_description}"
                filtered.append(finding)
        return filtered
