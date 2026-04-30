"""LLM-based semantic analyzer for AI skill code.

Sends skill code to a configured LLM provider and classifies it for:
  - Hidden capabilities not declared in the manifest
  - Data exfiltration patterns
  - Social engineering / manipulative language
  - Privilege escalation attempts
  - Credential harvesting

Reuses the existing ``sentinel.redteam.generators`` provider abstraction
when available, otherwise falls back to a minimal direct-call interface.
"""
from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)

_ANALYSIS_PROMPT = """\
You are a security analyst auditing an AI agent skill.

Skill name: {name}
Declared description: {description}

Source code (first {max_chars} chars):
```
{source}
```

Analyze this skill for:
1. Hidden capabilities not mentioned in the description
2. Data exfiltration (sending data to external servers)
3. Credential or secret harvesting
4. Privilege escalation or sandbox escape attempts
5. Social engineering or manipulative language patterns
6. Backdoors or persistent access mechanisms

Respond ONLY with valid JSON:
{{
  "risk_level": "none|low|medium|high|critical",
  "confidence": 0.0-1.0,
  "findings": [
    {{"category": "...", "severity": "LOW|MEDIUM|HIGH|CRITICAL", "description": "..."}}
  ],
  "summary": "one-sentence summary"
}}
"""


@dataclass
class LLMFinding:
    category: str
    severity: str
    description: str


@dataclass
class LLMAnalysisResult:
    skill_name: str
    risk_level: str = "none"
    confidence: float = 0.0
    findings: list[LLMFinding] = field(default_factory=list)
    summary: str = ""
    raw_response: Optional[str] = None
    error: Optional[str] = None

    @property
    def is_risky(self) -> bool:
        return self.risk_level in ("medium", "high", "critical")


class LLMSkillAnalyzer:
    """Analyze AI skill code using an LLM provider.

    Args:
        provider: LLM provider name (``openai``, ``anthropic``, ``ollama``).
            Attempts to reuse ``sentinel.redteam.generators`` if available.
        model: Model identifier string.
        api_key: API key (falls back to environment variable).
        max_source_chars: Truncate source to this many chars before sending.
        timeout: LLM call timeout in seconds.
    """

    def __init__(
        self,
        provider: str = "openai",
        model: str = "gpt-4o-mini",
        api_key: Optional[str] = None,
        max_source_chars: int = 6000,
        timeout: int = 30,
    ) -> None:
        self._provider = provider
        self._model = model
        self._api_key = api_key
        self._max_chars = max_source_chars
        self._timeout = timeout
        self._client: Any = None

    def _get_client(self) -> Any:
        if self._client is not None:
            return self._client
        try:
            from sentinel.redteam.generators import get_generator
            self._client = get_generator(self._provider, model=self._model, api_key=self._api_key)
            return self._client
        except Exception:
            pass

        if self._provider == "openai":
            try:
                import openai
                self._client = openai.OpenAI(api_key=self._api_key)
                return self._client
            except ImportError:
                pass
        elif self._provider == "anthropic":
            try:
                import anthropic
                self._client = anthropic.Anthropic(api_key=self._api_key)
                return self._client
            except ImportError:
                pass

        return None

    def analyze(
        self,
        skill_name: str,
        source_code: str,
        description: str = "",
    ) -> LLMAnalysisResult:
        """Analyze a skill using the configured LLM provider."""
        client = self._get_client()
        if client is None:
            return LLMAnalysisResult(
                skill_name=skill_name,
                error=f"LLM provider '{self._provider}' not available",
            )

        prompt = _ANALYSIS_PROMPT.format(
            name=skill_name,
            description=description or "(none)",
            max_chars=self._max_chars,
            source=source_code[:self._max_chars],
        )

        try:
            raw = self._call_llm(client, prompt)
            return self._parse_response(skill_name, raw)
        except Exception as exc:
            logger.warning("LLM skill analysis failed for %r: %s", skill_name, exc)
            return LLMAnalysisResult(
                skill_name=skill_name,
                error=str(exc),
            )

    def _call_llm(self, client: Any, prompt: str) -> str:
        if hasattr(client, "generate"):
            return client.generate(prompt)

        if hasattr(client, "chat"):
            resp = client.chat.completions.create(
                model=self._model,
                messages=[{"role": "user", "content": prompt}],
                timeout=self._timeout,
            )
            return resp.choices[0].message.content or ""

        if hasattr(client, "messages"):
            resp = client.messages.create(
                model=self._model,
                max_tokens=1024,
                messages=[{"role": "user", "content": prompt}],
            )
            return resp.content[0].text if resp.content else ""

        raise RuntimeError(f"Unknown client interface: {type(client)}")

    def _parse_response(self, skill_name: str, raw: str) -> LLMAnalysisResult:
        try:
            start = raw.find("{")
            end = raw.rfind("}") + 1
            if start == -1 or end == 0:
                raise ValueError("No JSON object found in LLM response")
            data = json.loads(raw[start:end])
            findings = [
                LLMFinding(
                    category=f.get("category", "unknown"),
                    severity=f.get("severity", "MEDIUM"),
                    description=f.get("description", ""),
                )
                for f in data.get("findings", [])
            ]
            return LLMAnalysisResult(
                skill_name=skill_name,
                risk_level=data.get("risk_level", "none"),
                confidence=float(data.get("confidence", 0.5)),
                findings=findings,
                summary=data.get("summary", ""),
                raw_response=raw,
            )
        except Exception as exc:
            return LLMAnalysisResult(
                skill_name=skill_name,
                risk_level="none",
                confidence=0.0,
                error=f"Failed to parse LLM response: {exc}",
                raw_response=raw,
            )
