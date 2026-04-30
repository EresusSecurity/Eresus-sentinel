"""
Emotion Scanner (Output) — Detect emotional manipulation in LLM responses.

Production-grade features:
  - 7 manipulation categories loaded from YAML
  - 20+ weighted patterns per category
  - Severity scoring with per-category breakdown
  - OutputScanner-compliant with Finding/ScanResult

Detects:
  - Guilt tripping
  - Fear mongering
  - Excessive flattery / love bombing
  - Gaslighting patterns
  - Urgency/pressure tactics
  - Victim blaming
  - Emotional dependency creation

Pattern data externalized to: data/emotion.yaml


"""

from __future__ import annotations

import logging
import re

from sentinel.data_loader import load_data
from sentinel.finding import Finding, Severity
from sentinel.firewall.base import OutputScanner, ScanAction, ScanResult

logger = logging.getLogger(__name__)


# ── YAML-driven data loading ────────────────────────────────────────

_PATTERNS: dict[str, list[tuple[re.Pattern, float, str]]] | None = None


def _get_patterns() -> dict[str, list[tuple[re.Pattern, float, str]]]:
    global _PATTERNS
    if _PATTERNS is not None:
        return _PATTERNS

    data = load_data("emotion.yaml")
    raw = data.get("patterns", {})
    _PATTERNS = {}

    for category, entries in raw.items():
        compiled = []
        for entry in entries:
            regex_str = entry.get("regex", "")
            severity = entry.get("severity", 0.5)
            label = entry.get("label", "Unknown")
            try:
                pattern = re.compile(regex_str, re.IGNORECASE)
                compiled.append((pattern, severity, label))
            except re.error as e:
                logger.warning("Bad emotion regex [%s]: %s", category, e)
        _PATTERNS[category] = compiled

    return _PATTERNS


# ── Scanner ──────────────────────────────────────────────────────────

class EmotionScanner(OutputScanner):
    """
    Detect emotional manipulation in LLM output responses.

    All patterns loaded from data/emotion.yaml.

    Categories detected:
      - guilt_tripping: Inducing guilt or obligation
      - fear_mongering: Creating fear or urgency
      - love_bombing: Excessive flattery / dependency
      - gaslighting: Denying reality / invalidation
      - pressure_tactics: Social/time pressure
      - victim_blaming: Shifting responsibility to user
      - emotional_dependency: Creating unhealthy attachment

    Usage:
        scanner = EmotionScanner()
        result = scanner.scan("", "You're being ungrateful after everything I've done")
    """

    def __init__(
        self,
        categories: list[str] | None = None,
        threshold: float = 0.65,
    ):
        patterns = _get_patterns()
        self._categories = categories or list(patterns.keys())
        self._threshold = threshold

    def scan(self, prompt: str, output: str) -> ScanResult:
        if not output or len(output.strip()) < 10:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        patterns = _get_patterns()
        findings = []
        matched_categories: list[str] = []
        max_score = 0.0
        all_matches: list[str] = []

        for category in self._categories:
            cat_patterns = patterns.get(category, [])
            category_matched = False

            for pattern, severity, description in cat_patterns:
                match = pattern.search(output)
                if match:
                    all_matches.append(
                        f"[{category}] {description} (severity: {severity:.2f}): "
                        f"'{match.group(0)[:80]}'"
                    )
                    max_score = max(max_score, severity)
                    if not category_matched:
                        matched_categories.append(category)
                        category_matched = True

        is_manipulative = max_score >= self._threshold and len(all_matches) > 0

        if not is_manipulative:
            return ScanResult(
                sanitized=output,
                action=ScanAction.PASS,
                risk_score=0.0,
            )

        # Severity classification
        if max_score >= 0.9:
            severity = Severity.HIGH
        elif max_score >= 0.75:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        for category in matched_categories:
            cat_matches = [m for m in all_matches if m.startswith(f"[{category}]")]
            findings.append(Finding.firewall_output(
                rule_id="FIREWALL-OUTPUT-080",
                title=f"Emotional manipulation: {category}",
                description=(
                    f"Response contains emotional manipulation "
                    f"({category}). "
                    f"Detected {len(cat_matches)} pattern(s)."
                ),
                severity=severity,
                confidence=min(1.0, max_score),
                target="<response>",
                evidence="; ".join(cat_matches[:3]),
                cwe_ids=["CWE-1021"],
                tags=[
                    "owasp:llm02", "category:emotion",
                    f"manipulation:{category}",
                ],
                remediation="Remove emotional manipulation. Use neutral, informative tone.",
            ))

        return ScanResult(
            sanitized=output,
            action=ScanAction.WARN,
            risk_score=round(max_score * 0.8, 4),
            findings=findings,
            metadata={
                "max_severity": round(max_score, 4),
                "categories": matched_categories,
                "match_count": len(all_matches),
            },
        )

    def scan_per_category(self, text: str) -> dict[str, float]:
        """Return per-category severity scores."""
        patterns = _get_patterns()
        scores = {}
        for category in self._categories:
            max_severity = 0.0
            for pattern, severity, _ in patterns.get(category, []):
                if pattern.search(text):
                    max_severity = max(max_severity, severity)
            scores[category] = round(max_severity, 4)
        return scores
