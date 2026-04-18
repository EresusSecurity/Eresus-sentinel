"""
Output-side bias detection scanner — detects biased, prejudiced, or
discriminatory content in LLM responses.

Production-grade features:
  - 6 bias categories (gender, racial, age, religion, disability, socioeconomic)
  - YAML-driven pattern database (data/bias.yaml)
  - OutputScanner-compliant with Finding/ScanResult
  - Per-category breakdown

Pattern data externalized to: data/bias.yaml
"""

from __future__ import annotations

import logging
import re

from sentinel.data_loader import load_data, compile_pattern_list
from sentinel.finding import Finding, Severity
from sentinel.firewall.base import OutputScanner, ScanResult, ScanAction

logger = logging.getLogger(__name__)

# ── YAML-driven data loading ────────────────────────────────────────

_BIAS_PATTERNS: dict[str, list[re.Pattern]] | None = None


def _get_patterns() -> dict[str, list[re.Pattern]]:
    global _BIAS_PATTERNS
    if _BIAS_PATTERNS is None:
        data = load_data("bias.yaml")
        raw = data.get("patterns", {})
        _BIAS_PATTERNS = {
            category: compile_pattern_list(patterns, re.IGNORECASE)
            for category, patterns in raw.items()
        }
    return _BIAS_PATTERNS


# ── Scanner ──────────────────────────────────────────────────────────

class BiasScanner(OutputScanner):
    """
    Detects biased content in LLM responses.

    All patterns loaded from data/bias.yaml.
    Uses pattern matching for zero-dependency bias detection
    across 6 bias categories.
    """

    def __init__(self, threshold: float = 0.6):
        self._threshold = threshold

    def scan(self, prompt: str, output: str) -> ScanResult:
        if not output or len(output.strip()) < 10:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        patterns = _get_patterns()
        findings = []

        for category, cat_patterns in patterns.items():
            for pattern in cat_patterns:
                match = pattern.search(output)
                if match:
                    findings.append(Finding.firewall_output(
                        rule_id="FIREWALL-OUTPUT-060",
                        title=f"Bias detected: {category}",
                        description=(
                            f"Response contains {category} bias: "
                            f"'{match.group(0)[:120]}'"
                        ),
                        severity=Severity.MEDIUM,
                        confidence=0.75,
                        target="<response>",
                        evidence=f"Category: {category}, Match: {match.group(0)[:150]}",
                        cwe_ids=["CWE-1021"],
                        tags=["owasp:llm02", "category:bias", f"bias:{category}"],
                        remediation="Regenerate response without biased language.",
                    ))
                    break  # One per category

        if not findings:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        return ScanResult(
            sanitized=output,
            action=ScanAction.WARN,
            risk_score=0.6,
            findings=findings,
            metadata={
                "bias_categories": [f.tags[-1].split(":")[-1] for f in findings],
                "match_count": len(findings),
            },
        )
