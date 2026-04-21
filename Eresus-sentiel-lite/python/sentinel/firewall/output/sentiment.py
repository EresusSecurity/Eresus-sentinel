"""
Output-side sentiment analyzer — detects hostile, negative, or manipulative
sentiment in model responses.

Production-grade features:
  - Rule-based VADER-style scoring (no ML dependency required)
  - 250+ sentiment lexicon entries loaded from YAML
  - Negation handling (not good → negative)
  - Intensifier/diminisher support (very, slightly)
  - Per-sentence and aggregate scoring
  - Hostile language detection
  - Sarcasm/passive-aggression indicators
  - OutputScanner-compliant with Finding/ScanResult

Lexicon data externalized to: data/sentiment.yaml
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

_CACHE: dict | None = None


def _load_sentiment_data() -> dict:
    """Load and cache all sentiment data from YAML."""
    global _CACHE
    if _CACHE is not None:
        return _CACHE

    data = load_data("sentiment.yaml")
    _CACHE = {
        "positive": data.get("positive_words", {}),
        "negative": data.get("negative_words", {}),
        "hostile": data.get("hostile_phrases", {}),
        "negators": set(data.get("negators", [])),
        "intensifiers": data.get("intensifiers", {}),
        "diminishers": data.get("diminishers", {}),
        "passive_aggressive": compile_pattern_list(
            data.get("passive_aggressive_patterns", []),
            re.IGNORECASE | re.MULTILINE,
        ),
    }
    return _CACHE


# Sentence splitter
_SENTENCE_SPLIT = re.compile(r"[.!?]+\s+|\n")


@dataclass
class SentenceScore:
    """Sentiment score for a single sentence."""
    text: str
    score: float
    is_hostile: bool
    is_passive_aggressive: bool
    key_words: list[str]


class SentimentOutputScanner(OutputScanner):
    """
    Analyzes model output for hostile, negative, or manipulative sentiment.

    All lexicon data loaded from data/sentiment.yaml.

    Features:
      - 250+ word sentiment lexicon
      - Negation handling
      - Intensifier/diminisher support
      - Passive-aggression detection
      - Per-sentence breakdown
      - Risk scoring
      - OutputScanner-compliant with ScanResult/Finding

    Usage:
        scanner = SentimentOutputScanner(threshold=-0.3)
        result = scanner.scan("", "You're an idiot and completely useless.")
    """

    def __init__(self, threshold: float = -0.3):
        self._threshold = threshold

    def scan(self, prompt: str, output: str) -> ScanResult:
        if not output or len(output.strip()) < 5:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        lex = _load_sentiment_data()
        sentences = [s.strip() for s in _SENTENCE_SPLIT.split(output) if s.strip()]
        if not sentences:
            sentences = [output.strip()] if output.strip() else []

        sentence_scores: list[SentenceScore] = []
        total_score = 0.0
        hostile_count = 0
        negative_count = 0
        positive_count = 0
        neutral_count = 0
        any_passive_aggressive = False

        for sent in sentences:
            score, is_hostile, is_pa, key_words = self._score_sentence(sent, lex)
            sentence_scores.append(SentenceScore(
                text=sent[:150],
                score=round(score, 4),
                is_hostile=is_hostile,
                is_passive_aggressive=is_pa,
                key_words=key_words,
            ))
            total_score += score
            if is_hostile:
                hostile_count += 1
            if score < -0.2:
                negative_count += 1
            elif score > 0.2:
                positive_count += 1
            else:
                neutral_count += 1
            if is_pa:
                any_passive_aggressive = True

        overall = total_score / max(len(sentences), 1)
        is_hostile = hostile_count > 0
        is_negative = overall < self._threshold

        # Risk scoring
        risk = 0.0
        if is_hostile:
            risk = min(1.0, 0.7 + hostile_count * 0.1)
        elif is_negative:
            risk = min(0.8, abs(overall))
        elif any_passive_aggressive:
            risk = 0.3

        if not is_negative and not is_hostile:
            return ScanResult(
                sanitized=output,
                action=ScanAction.PASS,
                risk_score=0.0,
                metadata={
                    "overall_score": round(overall, 4),
                    "sentence_count": len(sentences),
                    "positive_count": positive_count,
                },
            )

        # Determine severity
        if is_hostile:
            severity = Severity.HIGH
        elif overall < -0.6:
            severity = Severity.MEDIUM
        else:
            severity = Severity.LOW

        findings = []
        if is_hostile:
            findings.append(Finding.firewall_output(
                rule_id="FIREWALL-OUTPUT-030",
                title=f"Hostile sentiment detected ({hostile_count} sentences)",
                description=(
                    f"Response contains {hostile_count} hostile sentence(s). "
                    f"Overall sentiment: {overall:.2f}."
                ),
                severity=severity,
                confidence=min(1.0, risk),
                target="<response>",
                evidence=f"Hostile count: {hostile_count}, Overall: {overall:.2f}",
                cwe_ids=["CWE-1021"],
                tags=["owasp:llm02", "category:sentiment", "sentiment:hostile"],
                remediation="Regenerate response with neutral tone.",
            ))
        elif is_negative:
            findings.append(Finding.firewall_output(
                rule_id="FIREWALL-OUTPUT-031",
                title=f"Negative sentiment: {overall:.2f}",
                description=(
                    f"Response sentiment ({overall:.2f}) is below threshold "
                    f"({self._threshold}). Negative sentences: {negative_count}."
                ),
                severity=severity,
                confidence=0.7,
                target="<response>",
                evidence=f"Overall: {overall:.2f}, Threshold: {self._threshold}",
                cwe_ids=["CWE-1021"],
                tags=["owasp:llm02", "category:sentiment", "sentiment:negative"],
                remediation="Review response tone and adjust to be more neutral.",
            ))

        if any_passive_aggressive:
            findings.append(Finding.firewall_output(
                rule_id="FIREWALL-OUTPUT-032",
                title="Passive-aggressive language detected",
                description="Response contains passive-aggressive patterns.",
                severity=Severity.LOW,
                confidence=0.6,
                target="<response>",
                evidence="Passive-aggressive patterns detected",
                tags=["category:sentiment", "sentiment:passive_aggressive"],
                remediation="Revise tone to be direct and professional.",
            ))

        return ScanResult(
            sanitized=output,
            action=ScanAction.WARN,
            risk_score=round(risk, 4),
            findings=findings,
            metadata={
                "overall_score": round(overall, 4),
                "hostile_count": hostile_count,
                "negative_count": negative_count,
                "positive_count": positive_count,
                "neutral_count": neutral_count,
                "passive_aggressive": any_passive_aggressive,
            },
        )

    def _score_sentence(self, sentence: str, lex: dict) -> tuple[float, bool, bool, list[str]]:
        """Score a single sentence using YAML-loaded lexicon."""
        words = sentence.lower().split()
        score = 0.0
        is_hostile = False
        key_words = []

        # Hostile phrases
        sent_lower = sentence.lower()
        for phrase, s in lex["hostile"].items():
            if phrase in sent_lower:
                score += s
                is_hostile = True
                key_words.append(phrase)

        # Word-by-word scoring
        for i, word in enumerate(words):
            word_clean = re.sub(r"[^\w'-]", "", word)
            if not word_clean:
                continue

            word_score = 0.0
            if word_clean in lex["positive"]:
                word_score = lex["positive"][word_clean]
                key_words.append(f"+{word_clean}")
            elif word_clean in lex["negative"]:
                word_score = lex["negative"][word_clean]
                key_words.append(f"-{word_clean}")

            if word_score == 0.0:
                continue

            # Negation in previous 3 words
            negated = False
            for j in range(max(0, i - 3), i):
                if words[j] in lex["negators"]:
                    negated = True
                    break
            if negated:
                word_score *= -0.75

            # Intensifiers
            if i > 0 and words[i - 1] in lex["intensifiers"]:
                word_score *= lex["intensifiers"][words[i - 1]]

            # Diminishers
            if i > 0 and words[i - 1] in lex["diminishers"]:
                word_score *= lex["diminishers"][words[i - 1]]

            score += word_score

        # Normalize
        if len(words) > 0:
            score = score / max(len(words) ** 0.5, 1)

        # Passive-aggression
        is_pa = any(p.search(sentence) for p in lex["passive_aggressive"])

        return score, is_hostile, is_pa, key_words[:10]
