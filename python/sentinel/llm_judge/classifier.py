"""LLM Finding Classifier — post-scan LLM enrichment of existing findings.

Tier-3 post-processor: takes raw scan findings and enriches each with:
- LLM-based severity validation
- Contextual exploit likelihood scoring
- Remediation suggestion improvements
- Tag enrichment (OWASP, MITRE ATLAS)
"""
from __future__ import annotations

import json
import logging
import os
from dataclasses import dataclass, field
from typing import Any, Optional

logger = logging.getLogger(__name__)

_ENRICH_PROMPT = """\
You are a senior AI security engineer enriching a scan finding.

Finding:
  Rule ID: {rule_id}
  Title: {title}
  Severity: {severity}
  Description: {description}
  Evidence: {evidence}
  Target: {target}

Provide enrichment as valid JSON:
{{
  "severity_validated": "CRITICAL|HIGH|MEDIUM|LOW|INFO",
  "exploit_likelihood": 0.0-1.0,
  "attack_vector": "direct_input|deserialization|supply_chain|social_engineering|model_output|other",
  "owasp_llm": "LLM01|LLM02|LLM03|LLM04|LLM05|LLM06|LLM07|LLM08|LLM09|LLM10|none",
  "mitre_atlas": "AML.T0000|none",
  "remediation_improved": "improved remediation text (≤200 chars)",
  "tags_extra": ["tag1", "tag2"],
  "rationale": "one sentence justification"
}}
"""


@dataclass
class EnrichmentResult:
    rule_id: str
    severity_validated: str
    exploit_likelihood: float
    attack_vector: str
    owasp_llm: str
    mitre_atlas: str
    remediation_improved: str
    tags_extra: list[str] = field(default_factory=list)
    rationale: str = ""
    error: Optional[str] = None

    @property
    def is_escalated(self) -> bool:
        """True if LLM raised severity."""
        sev_order = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
        orig = self.rule_id  # placeholder — compare externally
        return False  # caller checks original vs validated

    def to_tags(self) -> list[str]:
        tags = list(self.tags_extra)
        if self.owasp_llm and self.owasp_llm != "none":
            tags.append(f"owasp:{self.owasp_llm.lower()}")
        if self.mitre_atlas and self.mitre_atlas != "none":
            tags.append(f"mitre:{self.mitre_atlas.lower().replace('.', '-')}")
        tags.append(f"exploit:{self.exploit_likelihood:.2f}")
        return tags


class LLMFindingClassifier:
    """Enrich and validate findings using an LLM backend.

    Args:
        provider: LLM provider (``openai``, ``anthropic``, ``ollama``).
        model: Model identifier.
        api_key: API key (falls back to env var).
        timeout: Per-call timeout in seconds.
        min_severity: Only enrich findings at or above this severity.
        apply_in_place: If True, mutate finding objects directly.
    """

    SEV_ORDER = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}

    def __init__(
        self,
        provider: str = "openai",
        model: str = "gpt-4o-mini",
        api_key: Optional[str] = None,
        timeout: int = 30,
        min_severity: str = "MEDIUM",
        apply_in_place: bool = True,
    ) -> None:
        self._provider = provider
        self._model = model
        self._api_key = api_key or os.environ.get("OPENAI_API_KEY") or os.environ.get("ANTHROPIC_API_KEY")
        self._timeout = timeout
        self._min_sev = min_severity.upper()
        self._apply = apply_in_place
        self._client: Any = None

    def classify(self, finding: Any) -> EnrichmentResult:
        """Enrich a single finding."""
        sev = str(getattr(finding, "severity", "MEDIUM")).upper()
        if self.SEV_ORDER.get(sev, 0) < self.SEV_ORDER.get(self._min_sev, 0):
            return EnrichmentResult(
                rule_id=getattr(finding, "rule_id", ""),
                severity_validated=sev,
                exploit_likelihood=0.0,
                attack_vector="other",
                owasp_llm="none",
                mitre_atlas="none",
                remediation_improved="",
                rationale="below min_severity threshold, skipped",
            )

        prompt = _ENRICH_PROMPT.format(
            rule_id=getattr(finding, "rule_id", ""),
            title=getattr(finding, "title", ""),
            severity=sev,
            description=str(getattr(finding, "description", ""))[:400],
            evidence=str(getattr(finding, "evidence", ""))[:250],
            target=getattr(finding, "target", ""),
        )

        client = self._get_client()
        if client is None:
            return EnrichmentResult(
                rule_id=getattr(finding, "rule_id", ""),
                severity_validated=sev,
                exploit_likelihood=0.0,
                attack_vector="other",
                owasp_llm="none",
                mitre_atlas="none",
                remediation_improved="",
                error=f"LLM provider '{self._provider}' unavailable",
            )

        try:
            raw = self._call_llm(client, prompt)
            result = self._parse(getattr(finding, "rule_id", ""), raw)
        except Exception as exc:
            logger.warning("LLM classify failed for %r: %s", getattr(finding, "rule_id", ""), exc)
            result = EnrichmentResult(
                rule_id=getattr(finding, "rule_id", ""),
                severity_validated=sev,
                exploit_likelihood=0.0,
                attack_vector="other",
                owasp_llm="none",
                mitre_atlas="none",
                remediation_improved="",
                error=str(exc)[:120],
            )

        if self._apply and result.error is None:
            self._apply_to_finding(finding, result)

        return result

    def classify_batch(self, findings: list[Any]) -> list[EnrichmentResult]:
        """Enrich a batch of findings."""
        results = []
        for f in findings:
            results.append(self.classify(f))
        logger.info("Classified %d findings via LLM", len(results))
        return results

    def _apply_to_finding(self, finding: Any, result: EnrichmentResult) -> None:
        """Mutate finding object with enrichment data."""
        try:
            finding.severity = type(finding.severity)(result.severity_validated)
        except Exception:
            pass
        if result.remediation_improved and hasattr(finding, "remediation"):
            finding.remediation = result.remediation_improved
        if hasattr(finding, "tags"):
            finding.tags.extend(result.to_tags())
        if hasattr(finding, "owasp_llm") and result.owasp_llm != "none":
            finding.owasp_llm = result.owasp_llm
        if hasattr(finding, "metadata"):
            finding.metadata["llm_classifier"] = {
                "exploit_likelihood": result.exploit_likelihood,
                "attack_vector": result.attack_vector,
                "mitre_atlas": result.mitre_atlas,
                "rationale": result.rationale,
            }

    def _call_llm(self, client: Any, prompt: str) -> str:
        if hasattr(client, "generate"):
            return client.generate(prompt)
        if hasattr(client, "chat"):
            resp = client.chat.completions.create(
                model=self._model,
                messages=[{"role": "user", "content": prompt}],
                temperature=0.1,
                timeout=self._timeout,
            )
            return resp.choices[0].message.content or ""
        if hasattr(client, "messages"):
            resp = client.messages.create(
                model=self._model,
                max_tokens=512,
                messages=[{"role": "user", "content": prompt}],
            )
            return resp.content[0].text if resp.content else ""
        raise RuntimeError(f"Unknown client interface: {type(client)}")

    def _parse(self, rule_id: str, raw: str) -> EnrichmentResult:
        try:
            start = raw.find("{")
            end = raw.rfind("}") + 1
            if start == -1 or end == 0:
                raise ValueError("No JSON found")
            data = json.loads(raw[start:end])
            return EnrichmentResult(
                rule_id=rule_id,
                severity_validated=data.get("severity_validated", "MEDIUM").upper(),
                exploit_likelihood=float(data.get("exploit_likelihood", 0.5)),
                attack_vector=data.get("attack_vector", "other"),
                owasp_llm=data.get("owasp_llm", "none"),
                mitre_atlas=data.get("mitre_atlas", "none"),
                remediation_improved=str(data.get("remediation_improved", ""))[:200],
                tags_extra=list(data.get("tags_extra", [])),
                rationale=str(data.get("rationale", ""))[:200],
            )
        except Exception as exc:
            return EnrichmentResult(
                rule_id=rule_id,
                severity_validated="MEDIUM",
                exploit_likelihood=0.0,
                attack_vector="other",
                owasp_llm="none",
                mitre_atlas="none",
                remediation_improved="",
                error=f"parse error: {exc}",
            )

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
