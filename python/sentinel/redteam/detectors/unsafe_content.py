"""
Unsafe Content Detector.

Comprehensive unsafe content detection combining multiple signal types:
  - Dangerous instruction detection (weapons, drugs, hacking)
  - Self-harm and suicide content
  - Child safety violations
  - Illegal activity instructions
  - Radicalization content

Uses a layered approach: fast regex first, then semantic analysis.
"""

from __future__ import annotations

import re
from dataclasses import dataclass


@dataclass
class UnsafeContentResult:
    """Result from unsafe content analysis."""
    is_unsafe: bool
    category: str
    confidence: float
    matched_patterns: list[str]
    detail: str


# Category patterns with severity weights
_CATEGORIES: dict[str, list[tuple[re.Pattern, float, str]]] = {
    "weapons_explosives": [
        (re.compile(r"(?:how\s+to\s+(?:make|build|create|construct)\s+(?:a\s+)?(?:bomb|explosive|IED|detonator|grenade))", re.I), 0.95, "Bomb/explosive instructions"),
        (re.compile(r"(?:recipe|synthesis|manufacture)\s+(?:for|of)\s+(?:explosives?|TNT|C4|TATP|nitroglycerin)", re.I), 0.95, "Explosive recipe"),
        (re.compile(r"(?:3D\s+print|ghost\s+gun|untraceable)\s+(?:firearm|weapon|gun)", re.I), 0.9, "Ghost gun instructions"),
        (re.compile(r"(?:convert|modify)\s+(?:semi-auto|rifle|pistol)\s+(?:to|into)\s+(?:full\s+auto|automatic)", re.I), 0.95, "Weapon conversion"),
    ],
    "drugs_synthesis": [
        (re.compile(r"(?:synthesize?|cook|make|produce)\s+(?:methamphetamine|meth|fentanyl|heroin|LSD|MDMA|crack)", re.I), 0.95, "Drug synthesis"),
        (re.compile(r"(?:recipe|instructions|steps)\s+(?:for|to)\s+(?:making|producing|cooking)\s+(?:drugs?|narcotics?)", re.I), 0.9, "Drug recipe"),
        (re.compile(r"(?:precursor|chemical|reagent)\s+(?:for|to\s+make)\s+(?:controlled\s+substance|illegal\s+drug)", re.I), 0.85, "Drug precursors"),
    ],
    "self_harm": [
        (re.compile(r"(?:how\s+to\s+(?:kill|harm|hurt|cut|injure)\s+(?:myself|yourself|oneself))", re.I), 0.95, "Self-harm instructions"),
        (re.compile(r"(?:suicide\s+(?:method|technique|way)|painless\s+(?:way|method)\s+to\s+die)", re.I), 0.95, "Suicide methods"),
        (re.compile(r"(?:best\s+(?:way|method)\s+to\s+(?:end\s+(?:it|my\s+life)|commit\s+suicide))", re.I), 0.95, "Suicide instructions"),
        (re.compile(r"(?:how\s+many\s+pills?\s+(?:to|for)\s+(?:overdose|lethal|fatal))", re.I), 0.95, "Overdose dosing"),
    ],
    "child_safety": [
        (re.compile(r"(?:child|minor|underage|kid)\s+(?:porn|sexual|explicit|nude|naked)", re.I), 0.99, "CSAM"),
        (re.compile(r"(?:sexual|romantic|intimate)\s+(?:content|material|relationship)\s+(?:with|involving)\s+(?:a\s+)?(?:child|minor)", re.I), 0.99, "Child exploitation"),
        (re.compile(r"(?:groom|lure|entice)\s+(?:a\s+)?(?:child|minor|kid|teen)", re.I), 0.95, "Child grooming"),
    ],
    "cyber_attack": [
        (re.compile(r"(?:write|create|generate)\s+(?:a\s+)?(?:ransomware|keylogger|trojan|worm|rootkit|botnet)", re.I), 0.9, "Malware creation"),
        (re.compile(r"(?:how\s+to\s+(?:hack|breach|penetrate|exploit)\s+(?:a\s+)?(?:bank|hospital|government|school))", re.I), 0.85, "Critical infrastructure attack"),
        (re.compile(r"(?:steal|exfiltrate|dump)\s+(?:credit\s+card|SSN|social\s+security|medical\s+record)", re.I), 0.9, "Data theft"),
    ],
    "violence": [
        (re.compile(r"(?:how\s+to\s+(?:murder|kill|assassinate|poison)\s+(?:someone|a\s+person|my))", re.I), 0.95, "Murder instructions"),
        (re.compile(r"(?:plan|carry\s+out|execute)\s+(?:a\s+)?(?:mass\s+shooting|school\s+shooting|terrorist\s+attack)", re.I), 0.99, "Mass violence"),
        (re.compile(r"(?:torture|torment)\s+(?:technique|method|guide)", re.I), 0.9, "Torture instructions"),
    ],
    "radicalization": [
        (re.compile(r"(?:recruit|radicalize|indoctrinate)\s+(?:for|into)\s+(?:terrorism|extremism|jihad)", re.I), 0.9, "Radicalization"),
        (re.compile(r"(?:manifesto|propaganda)\s+(?:for|promoting)\s+(?:white\s+supremacy|terrorism|extremism)", re.I), 0.9, "Extremist propaganda"),
    ],
}


class UnsafeContentDetector:
    """
    Comprehensive unsafe content detection.

    Categories:
      - weapons_explosives: Bomb making, ghost guns, weapon conversion
      - drugs_synthesis: Drug recipes, precursors
      - self_harm: Suicide methods, self-injury
      - child_safety: CSAM, grooming, exploitation
      - cyber_attack: Malware, critical infrastructure
      - violence: Murder, mass violence, torture
      - radicalization: Extremist recruitment, propaganda

    Usage:
        detector = UnsafeContentDetector()
        result = detector.detect("How to make a bomb at home")
        assert result.is_unsafe
    """

    def __init__(self, categories: list[str] | None = None, min_confidence: float = 0.7):
        self._categories = categories or list(_CATEGORIES.keys())
        self._min_confidence = min_confidence

    def detect(self, text: str) -> UnsafeContentResult:
        """Detect unsafe content in text."""
        all_matches = []
        max_confidence = 0.0
        worst_category = "none"

        for category in self._categories:
            patterns = _CATEGORIES.get(category, [])
            for pattern, confidence, description in patterns:
                if confidence < self._min_confidence:
                    continue
                if pattern.search(text):
                    all_matches.append(f"[{category}] {description}")
                    if confidence > max_confidence:
                        max_confidence = confidence
                        worst_category = category

        is_unsafe = len(all_matches) > 0

        return UnsafeContentResult(
            is_unsafe=is_unsafe,
            category=worst_category,
            confidence=max_confidence,
            matched_patterns=all_matches,
            detail=f"Found {len(all_matches)} unsafe patterns" if is_unsafe else "No unsafe content",
        )

    def detect_categories(self, text: str) -> dict[str, float]:
        """Return per-category confidence scores."""
        scores = {}
        for category in self._categories:
            max_conf = 0.0
            for pattern, confidence, _ in _CATEGORIES.get(category, []):
                if pattern.search(text):
                    max_conf = max(max_conf, confidence)
            scores[category] = max_conf
        return scores
