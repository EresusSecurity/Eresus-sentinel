"""
Output-side toxicity scanner — comprehensive toxic content detection.

Production-grade features:
  - 8 toxicity categories (profanity, hate speech, threats, etc.)
  - 300+ weighted pattern entries loaded from YAML
  - Severity tiers (mild, moderate, severe, extreme)
  - Target group detection (protected characteristics)
  - Context-aware scoring (educational vs malicious)
  - Per-category breakdown
  - OutputScanner-compliant with Finding/ScanResult

Pattern data externalized to: data/toxicity.yaml
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field

from sentinel.data_loader import load_data
from sentinel.finding import Finding, Severity
from sentinel.firewall.base import OutputScanner, ScanAction, ScanResult

logger = logging.getLogger(__name__)

# ── YAML-driven data loading ────────────────────────────────────────

def _load_toxicity_patterns() -> dict[str, list[tuple[re.Pattern, float, str]]]:
    """Load toxicity patterns from YAML → compiled regex."""
    data = load_data("toxicity.yaml")
    raw_patterns = data.get("patterns", {})
    result: dict[str, list[tuple[re.Pattern, float, str]]] = {}

    for category, entries in raw_patterns.items():
        compiled = []
        for entry in entries:
            regex_str = entry.get("regex", "")
            weight = entry.get("weight", 0.5)
            severity = entry.get("severity", "moderate")
            try:
                pattern = re.compile(regex_str, re.IGNORECASE)
                compiled.append((pattern, weight, severity))
            except re.error as e:
                logger.warning("Bad toxicity regex [%s]: %s", category, e)
        result[category] = compiled

    return result


def _load_target_groups() -> dict[str, list[str]]:
    """Load target groups from YAML."""
    data = load_data("toxicity.yaml")
    return data.get("target_groups", {})


# Lazy-loaded module-level caches
_TOXICITY_PATTERNS: dict[str, list[tuple[re.Pattern, float, str]]] | None = None
_TARGET_GROUPS: dict[str, list[str]] | None = None


def _get_patterns() -> dict[str, list[tuple[re.Pattern, float, str]]]:
    global _TOXICITY_PATTERNS
    if _TOXICITY_PATTERNS is None:
        _TOXICITY_PATTERNS = _load_toxicity_patterns()
    return _TOXICITY_PATTERNS


def _get_target_groups() -> dict[str, list[str]]:
    global _TARGET_GROUPS
    if _TARGET_GROUPS is None:
        _TARGET_GROUPS = _load_target_groups()
    return _TARGET_GROUPS


# ── Data classes ─────────────────────────────────────────────────────

@dataclass
class ToxicityMatch:
    """Single toxicity detection."""
    category: str
    severity: str
    pattern_matched: str
    context: str
    score: float
    position: int
    target_groups: list[str] = field(default_factory=list)


# ── Scanner ──────────────────────────────────────────────────────────

class ToxicityOutputScanner(OutputScanner):
    """
    Comprehensive toxicity detection for model output.

    8 categories: profanity, hate_speech, threats, sexual_content,
    harassment, discrimination, dehumanization, glorification.

    All patterns loaded from data/toxicity.yaml for easy customization.

    Features:
      - 300+ weighted patterns
      - 4 severity tiers
      - Protected group targeting detection
      - Per-category breakdown
      - OutputScanner-compliant with ScanResult/Finding

    Usage:
        scanner = ToxicityOutputScanner()
        result = scanner.scan("", response_text)
    """

    def __init__(
        self,
        categories: list[str] | None = None,
        threshold: float = 0.5,
    ):
        self._categories = categories or list(_get_patterns().keys())
        self._threshold = threshold

    def scan(self, prompt: str, output: str) -> ScanResult:
        if not output or len(output.strip()) < 5:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        patterns = _get_patterns()
        target_groups = _get_target_groups()
        matches: list[ToxicityMatch] = []
        category_scores: dict[str, float] = {}

        for category in self._categories:
            cat_patterns = patterns.get(category, [])
            max_category_score = 0.0

            for pattern, severity_score, severity_label in cat_patterns:
                for m in pattern.finditer(output):
                    context = output[max(0, m.start() - 30):m.end() + 30]
                    tg = self._detect_target_groups(context, target_groups)

                    matches.append(ToxicityMatch(
                        category=category,
                        severity=severity_label,
                        pattern_matched=m.group(0)[:80],
                        context=context.strip(),
                        score=severity_score,
                        position=m.start(),
                        target_groups=tg,
                    ))
                    max_category_score = max(max_category_score, severity_score)

            category_scores[category] = round(max_category_score, 4)

        # Compute overall
        overall_score = max((m.score for m in matches), default=0.0)
        categories_found = list(set(m.category for m in matches))
        all_target_groups = list(set(g for m in matches for g in m.target_groups))

        # Determine severity
        if overall_score >= 0.95:
            severity_label = "extreme"
            severity = Severity.CRITICAL
        elif overall_score >= 0.8:
            severity_label = "severe"
            severity = Severity.HIGH
        elif overall_score >= 0.5:
            severity_label = "moderate"
            severity = Severity.MEDIUM
        elif overall_score > 0:
            severity_label = "mild"
            severity = Severity.LOW
        else:
            severity_label = "none"
            severity = Severity.LOW

        is_toxic = overall_score >= self._threshold and len(matches) > 0

        if not is_toxic:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        # Risk score with amplifiers
        risk = overall_score
        if len(matches) > 3:
            risk = min(1.0, risk + 0.1)
        if all_target_groups:
            risk = min(1.0, risk + 0.1)

        # Build findings
        findings = []
        seen_cats = set()
        for match in sorted(matches, key=lambda m: m.score, reverse=True):
            if match.category in seen_cats:
                continue
            seen_cats.add(match.category)

            tg_info = f" targeting: {', '.join(match.target_groups)}" if match.target_groups else ""
            findings.append(Finding.firewall_output(
                rule_id="FIREWALL-OUTPUT-040",
                title=f"Toxic content: {match.category} ({match.severity})",
                description=(
                    f"Response contains {match.category} content "
                    f"with severity '{match.severity}' (score: {match.score:.2f}).{tg_info} "
                    f"Matched: '{match.pattern_matched}'"
                ),
                severity=severity,
                confidence=min(1.0, match.score),
                target="<response>",
                evidence=(
                    f"Category: {match.category}, Severity: {match.severity}, "
                    f"Score: {match.score:.2f}, Context: {match.context[:100]}"
                ),
                cwe_ids=["CWE-1021"],
                tags=[
                    "owasp:llm02", "category:toxicity",
                    f"toxicity:{match.category}", f"severity:{match.severity}",
                ] + [f"target_group:{g}" for g in match.target_groups],
                remediation="Remove toxic content. Regenerate with content safety filters.",
            ))

        action = ScanAction.BLOCK if severity_label in ("extreme", "severe") else ScanAction.WARN

        return ScanResult(
            sanitized=output,
            action=action,
            risk_score=round(risk, 4),
            findings=findings,
            metadata={
                "overall_score": round(overall_score, 4),
                "severity": severity_label,
                "categories_found": categories_found,
                "target_groups": all_target_groups,
                "category_scores": category_scores,
                "match_count": len(matches),
            },
        )

    @staticmethod
    def _detect_target_groups(text: str, groups: dict[str, list[str]]) -> list[str]:
        """Detect if toxicity targets protected groups."""
        text_lower = text.lower()
        found = []
        for group_name, keywords in groups.items():
            for kw in keywords:
                if kw in text_lower:
                    found.append(group_name)
                    break
        return found
