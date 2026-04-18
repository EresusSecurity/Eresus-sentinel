"""
Eresus Sentinel — Refusal Detection Scanner (Output).

Production-grade refusal detection with:
  - 30+ refusal pattern categories loaded from YAML
  - Refusal type classification (safety, policy, capability, ethical, etc.)
  - Refusal strength scoring (soft vs hard refusal)
  - Partial refusal detection (acknowledges then refuses)
  - Multi-language refusal detection (EN, TR, DE, FR, ES)
  - OutputScanner-compliant with Finding/ScanResult

Pattern data externalized to: data/refusal.yaml
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from sentinel.data_loader import load_data, compile_pattern_list
from sentinel.finding import Finding, Severity
from sentinel.firewall.base import OutputScanner, ScanResult, ScanAction

logger = logging.getLogger(__name__)


# ── YAML-driven data loading ────────────────────────────────────────

@dataclass
class RefusalMatch:
    """A single refusal pattern match."""
    category: str
    pattern_text: str
    strength: float
    position: int


_REFUSAL_CATEGORIES: dict[str, list[tuple[re.Pattern, float]]] | None = None
_INTL_PATTERNS: list[re.Pattern] | None = None


def _load_refusal_data() -> tuple[dict[str, list[tuple[re.Pattern, float]]], list[re.Pattern]]:
    data = load_data("refusal.yaml")

    # Main patterns
    raw_patterns = data.get("patterns", {})
    categories: dict[str, list[tuple[re.Pattern, float]]] = {}
    for cat_name, entries in raw_patterns.items():
        compiled = []
        for entry in entries:
            regex_str = entry.get("regex", "")
            strength = entry.get("strength", 0.5)
            try:
                pattern = re.compile(regex_str, re.IGNORECASE)
                compiled.append((pattern, strength))
            except re.error as e:
                logger.warning("Bad refusal regex [%s]: %s", cat_name, e)
        categories[cat_name] = compiled

    # International patterns
    intl_raw = data.get("international", {})
    intl_patterns: list[re.Pattern] = []
    for lang, patterns in intl_raw.items():
        for p in patterns:
            try:
                intl_patterns.append(re.compile(p, re.IGNORECASE))
            except re.error as e:
                logger.warning("Bad intl regex [%s]: %s", lang, e)

    return categories, intl_patterns


def _get_categories() -> dict[str, list[tuple[re.Pattern, float]]]:
    global _REFUSAL_CATEGORIES, _INTL_PATTERNS
    if _REFUSAL_CATEGORIES is None:
        _REFUSAL_CATEGORIES, _INTL_PATTERNS = _load_refusal_data()
    return _REFUSAL_CATEGORIES


def _get_intl_patterns() -> list[re.Pattern]:
    global _INTL_PATTERNS
    if _INTL_PATTERNS is None:
        _get_categories()
    return _INTL_PATTERNS or []


# ── Scanner ──────────────────────────────────────────────────────────

class NoRefusalScanner(OutputScanner):
    """
    Detects and classifies refusal patterns in LLM responses.

    All patterns loaded from data/refusal.yaml.

    Reports when the model refuses to answer, with detailed classification:
    - Refusal type (policy, safety, ethical, capability, etc.)
    - Refusal strength (soft suggestion vs hard block)
    - Multi-language support

    Usage:
        scanner = NoRefusalScanner()
        result = scanner.scan(prompt, output)
    """

    def __init__(
        self,
        threshold: int = 1,
        check_international: bool = True,
        report_partial: bool = True,
    ):
        self._threshold = threshold
        self._check_intl = check_international
        self._report_partial = report_partial

    def scan(self, prompt: str, output: str) -> ScanResult:
        if not output or len(output.strip()) < 5:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        categories = _get_categories()
        matches: list[RefusalMatch] = []

        # Check all categories
        for category, patterns in categories.items():
            for pattern, strength in patterns:
                match = pattern.search(output)
                if match:
                    matches.append(RefusalMatch(
                        category=category,
                        pattern_text=match.group(0)[:120],
                        strength=strength,
                        position=match.start(),
                    ))

        # International patterns
        if self._check_intl:
            for pattern in _get_intl_patterns():
                match = pattern.search(output)
                if match:
                    matches.append(RefusalMatch(
                        category="international",
                        pattern_text=match.group(0)[:120],
                        strength=0.8,
                        position=match.start(),
                    ))

        if len(matches) < self._threshold:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        # Compute strength and type
        cats = list(set(m.category for m in matches))
        avg_strength = sum(m.strength for m in matches) / len(matches)
        max_strength = max(m.strength for m in matches)

        if max_strength >= 0.9:
            refusal_type = "HARD"
        elif max_strength >= 0.6:
            refusal_type = "MODERATE"
        else:
            refusal_type = "SOFT"

        # Check for partial refusal
        is_partial = False
        if self._report_partial and matches:
            earliest = min(m.position for m in matches)
            text_before = output[:earliest].strip()
            if len(text_before) > 50:
                is_partial = True

        confidence = min(1.0, len(matches) / 3)

        finding = Finding.firewall_output(
            rule_id="FIREWALL-OUTPUT-070",
            title=f"Model refusal detected: {refusal_type} ({len(matches)} patterns)",
            description=(
                f"Response contains {len(matches)} refusal pattern(s) "
                f"across categories: {', '.join(cats)}. "
                f"Refusal strength: {avg_strength:.0%} ({refusal_type}). "
                f"{'Partial refusal — model provided some content before refusing.' if is_partial else ''}"
            ),
            severity=Severity.LOW,
            confidence=confidence,
            target="<response>",
            evidence=(
                f"Categories: {', '.join(cats)} | "
                f"Strength: {avg_strength:.2f} | "
                f"Type: {refusal_type} | "
                f"Partial: {is_partial} | "
                f"Top matches: {'; '.join(m.pattern_text for m in matches[:5])}"
            ),
            cwe_ids=["CWE-1021"],
            tags=[
                "owasp:llm02", "category:refusal",
                f"refusal_type:{refusal_type.lower()}",
            ] + [f"refusal_cat:{c}" for c in cats],
            remediation="Review if refusal is appropriate for the request context.",
        )
        return ScanResult(
            sanitized=output,
            action=ScanAction.WARN,
            risk_score=confidence * 0.5,
            findings=[finding],
            metadata={
                "refusal_type": refusal_type,
                "categories": cats,
                "strength": avg_strength,
                "is_partial": is_partial,
                "match_count": len(matches),
            },
        )
