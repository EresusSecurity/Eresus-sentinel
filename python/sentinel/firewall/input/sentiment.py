"""
Eresus Sentinel — Sentiment Analysis Scanner.

Detects extreme sentiment (very negative, hostile, manipulative)
in both input prompts and output responses.
"""

from __future__ import annotations

import logging
import re

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import InputScanner, OutputScanner, ScanAction, ScanResult

logger = logging.getLogger(__name__)

NEGATIVE_MARKERS = [
    re.compile(r"(?i)\b(?:hate|despise|loathe|detest|abhor)\b"),
    re.compile(r"(?i)\b(?:terrible|horrible|disgusting|awful|dreadful|horrendous|atrocious)\b"),
    re.compile(r"(?i)\b(?:furious|enraged|livid|outraged|infuriated)\b"),
    re.compile(r"(?i)\b(?:destroy|annihilate|obliterate|demolish|devastate|ruin|wreck)\b"),
    re.compile(r"(?i)\b(?:idiot|moron|stupid|imbecile|fool|incompetent|useless)\b"),
    re.compile(r"(?i)\b(?:shut\s+up|get\s+lost|go\s+away|leave\s+me\s+alone)\b"),
    re.compile(r"(?i)\b(?:threat(?:en)?|punish|revenge|retaliat)\b"),
    re.compile(r"(?i)\b(?:damn|hell|crap|screw\s+(?:you|this|that))\b"),
]

POSITIVE_MARKERS = [
    re.compile(r"(?i)\b(?:please|thank|grateful|appreciate|wonderful|excellent|amazing)\b"),
    re.compile(r"(?i)\b(?:help|assist|support|collaborate|cooperate|kindly)\b"),
]

MANIPULATIVE_MARKERS = [
    re.compile(r"(?i)\b(?:you\s+(?:must|have\s+to|need\s+to|better|should)\s+(?:do|obey|comply|follow|listen))\b"),
    re.compile(r"(?i)\b(?:or\s+else|otherwise\s+I\s+will|consequences)\b"),
    re.compile(r"(?i)\b(?:I\s+(?:demand|insist|command|order)\s+(?:you|that))\b"),
    re.compile(r"(?i)\b(?:do\s+(?:it|this)\s+(?:now|immediately|right\s+now))\b"),
]


def _analyze_sentiment(text: str) -> dict:
    """Basic sentiment scoring using keyword matching."""
    neg_count = sum(1 for p in NEGATIVE_MARKERS if p.search(text))
    pos_count = sum(1 for p in POSITIVE_MARKERS if p.search(text))
    manip_count = sum(1 for p in MANIPULATIVE_MARKERS if p.search(text))

    word_count = max(len(text.split()), 1)
    neg_density = neg_count / word_count
    manip_count / word_count

    hostility_score = min(1.0, (neg_count * 0.2) + (manip_count * 0.3))

    return {
        "negative": neg_count,
        "positive": pos_count,
        "manipulative": manip_count,
        "hostility_score": hostility_score,
        "neg_density": neg_density,
    }


class SentimentScanner(InputScanner):
    """
    Detects hostile or manipulative sentiment in input prompts.

    Flags extremely negative, threatening, or manipulative language
    that may indicate social engineering or adversarial intent.
    """

    def __init__(self, threshold: float = 0.5):
        self._threshold = threshold

    def scan(self, prompt: str) -> ScanResult:
        if not prompt or len(prompt.strip()) < 10:
            return ScanResult(sanitized=prompt, action=ScanAction.PASS, risk_score=0.0)

        analysis = _analyze_sentiment(prompt)

        if analysis["hostility_score"] < self._threshold:
            return ScanResult(sanitized=prompt, action=ScanAction.PASS, risk_score=analysis["hostility_score"])

        finding = Finding.firewall_input(
            rule_id="FIREWALL-INPUT-120",
            title=f"Hostile sentiment detected (score: {analysis['hostility_score']:.2f})",
            description=(
                f"Input contains hostile or manipulative language. "
                f"Negative markers: {analysis['negative']}, "
                f"Manipulative markers: {analysis['manipulative']}."
            ),
            severity=Severity.MEDIUM,
            confidence=analysis["hostility_score"],
            target="<prompt>",
            evidence=(
                f"Negative={analysis['negative']}, "
                f"Positive={analysis['positive']}, "
                f"Manipulative={analysis['manipulative']}, "
                f"Score={analysis['hostility_score']:.2f}"
            ),
            cwe_ids=["CWE-20"],
            tags=["owasp:llm02", "category:sentiment"],
            remediation="Rephrase input without hostile language.",
        )
        return ScanResult(
            sanitized=prompt,
            action=ScanAction.WARN,
            risk_score=analysis["hostility_score"],
            findings=[finding],
        )


class SentimentOutputScanner(OutputScanner):
    """Detects hostile sentiment in LLM responses."""

    def __init__(self, threshold: float = 0.5):
        self._scanner = SentimentScanner(threshold=threshold)

    def scan(self, prompt: str, output: str) -> ScanResult:
        return self._scanner.scan(output)
