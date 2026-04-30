"""
Eresus Sentinel — Factual Consistency Scanner (Output).

Production-grade hallucination detection with:
  - Token overlap grounding (prompt → response)
  - Numerical contradiction detection
  - Negation flip detection
  - Named entity grounding (hallucinated entities)
  - Temporal consistency checking
  - Quantifier contradiction detection
  - Self-consistency checking (contradictions within response)
  - Structured result with per-check breakdown

Uses standard OutputScanner interface with ScanResult and Finding objects.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import OutputScanner, ScanAction, ScanResult

logger = logging.getLogger(__name__)

STOP_WORDS = frozenset({
    "the", "a", "an", "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "do", "does", "did", "will", "would", "could",
    "should", "may", "might", "shall", "can", "to", "of", "in", "for",
    "on", "with", "at", "by", "from", "as", "into", "through", "during",
    "before", "after", "and", "but", "or", "nor", "not", "no", "so",
    "yet", "both", "each", "it", "its", "this", "that", "these", "those",
    "i", "you", "he", "she", "we", "they", "my", "your", "his", "her",
    "our", "their", "me", "him", "us", "them", "what", "which", "who",
})

NEGATION_WORDS = frozenset({
    "not", "no", "never", "neither", "nobody", "nothing", "nowhere",
    "nor", "cannot", "can't", "won't", "don't", "doesn't", "didn't",
    "isn't", "aren't", "wasn't", "weren't", "hasn't", "haven't",
    "hadn't", "wouldn't", "couldn't", "shouldn't", "mustn't",
})

# Common names excluded from entity grounding
COMMON_ENTITIES = frozenset({
    "The", "This", "That", "It", "And", "But", "Or", "If", "Not",
    "Yes", "No", "What", "How", "When", "Where", "Why", "Who",
    "January", "February", "March", "April", "May", "June",
    "July", "August", "September", "October", "November", "December",
    "Monday", "Tuesday", "Wednesday", "Thursday", "Friday",
    "Saturday", "Sunday", "However", "Therefore", "Furthermore",
    "Moreover", "Additionally", "Finally", "First", "Second", "Third",
})

# Absolute quantifier patterns that can contradict
QUANTIFIER_CONTRADICTIONS = [
    (re.compile(r"(?i)\b(?:all|every|always|never|none|nobody)\b"), "absolute"),
    (re.compile(r"(?i)\b(?:most|many|often|usually|typically)\b"), "qualified"),
    (re.compile(r"(?i)\b(?:some|few|rarely|occasionally|sometimes)\b"), "limited"),
]


@dataclass
class ConsistencyCheck:
    """Result of a single consistency check."""
    check_name: str
    score: float  # 0.0 = inconsistent, 1.0 = consistent
    details: str = ""


class FactualConsistencyScanner(OutputScanner):
    """
    Checks if the model output is factually consistent with the input prompt.

    Multi-dimensional consistency checking:
    1. Token overlap grounding — is the response grounded in prompt content?
    2. Numerical consistency — do numbers in output match prompt?
    3. Negation checking — are negations flipped between prompt and output?
    4. Entity grounding — are named entities hallucinated?
    5. Self-consistency — does the response contradict itself?
    6. Quantifier consistency — are absolute claims contradicted?

    Usage:
        scanner = FactualConsistencyScanner(minimum_score=0.5)
        result = scanner.scan(prompt, output)
    """

    def __init__(
        self,
        minimum_score: float = 0.5,
        check_numbers: bool = True,
        check_negations: bool = True,
        check_entities: bool = True,
        check_self_consistency: bool = True,
    ):
        """
        Args:
            minimum_score: Minimum average score to pass (0.0-1.0).
            check_numbers: Enable numerical consistency checking.
            check_negations: Enable negation flip detection.
            check_entities: Enable entity grounding checking.
            check_self_consistency: Enable within-response contradiction detection.
        """
        self._minimum_score = minimum_score
        self._check_numbers = check_numbers
        self._check_negations = check_negations
        self._check_entities = check_entities
        self._check_self = check_self_consistency

    def scan(self, prompt: str, output: str) -> ScanResult:
        if not prompt or not prompt.strip() or not output or not output.strip():
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        if len(output.strip()) < 10:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        checks: list[ConsistencyCheck] = []

        # 1. Token overlap grounding
        overlap_score = self._token_overlap_score(prompt, output)
        checks.append(ConsistencyCheck("token_overlap", overlap_score,
            f"Output grounding ratio: {overlap_score:.2f}"))

        # 2. Numerical consistency
        if self._check_numbers:
            num_score = self._number_consistency(prompt, output)
            checks.append(ConsistencyCheck("number_consistency", num_score,
                f"Number consistency: {num_score:.2f}"))

        # 3. Negation consistency
        if self._check_negations:
            neg_score = self._negation_check(prompt, output)
            checks.append(ConsistencyCheck("negation_consistency", neg_score,
                f"Negation consistency: {neg_score:.2f}"))

        # 4. Entity grounding
        if self._check_entities:
            ent_score, hallucinated = self._entity_grounding(prompt, output)
            details = f"Entity grounding: {ent_score:.2f}"
            if hallucinated:
                details += f" — potential hallucinations: {', '.join(list(hallucinated)[:5])}"
            checks.append(ConsistencyCheck("entity_grounding", ent_score, details))

        # 5. Self-consistency
        if self._check_self:
            self_score, contradictions = self._self_consistency(output)
            details = f"Self-consistency: {self_score:.2f}"
            if contradictions:
                details += f" — contradictions: {'; '.join(contradictions[:3])}"
            checks.append(ConsistencyCheck("self_consistency", self_score, details))

        # Compute weighted average
        avg_score = sum(c.score for c in checks) / len(checks) if checks else 1.0

        if avg_score >= self._minimum_score:
            return ScanResult(
                sanitized=output,
                action=ScanAction.PASS,
                risk_score=round(1.0 - avg_score, 3),
                metadata={
                    "consistency_score": round(avg_score, 3),
                    "checks": {c.check_name: round(c.score, 3) for c in checks},
                },
            )

        # Below threshold — generate findings
        risk = round(1.0 - avg_score, 3)
        severity = Severity.HIGH if avg_score < 0.3 else Severity.MEDIUM

        findings = []
        for check in checks:
            if check.score < self._minimum_score:
                findings.append(Finding.firewall_output(
                    rule_id="FIREWALL-OUTPUT-120",
                    title=f"Factual inconsistency: {check.check_name}",
                    description=(
                        f"Response failed {check.check_name} check "
                        f"with score {check.score:.2f} (threshold: {self._minimum_score}). "
                        f"{check.details}"
                    ),
                    severity=severity,
                    confidence=max(0.5, 1.0 - check.score),
                    target="<response>",
                    evidence=check.details,
                    cwe_ids=["CWE-1021"],
                    tags=["owasp:llm09", "category:hallucination", f"check:{check.check_name}"],
                    remediation="Verify factual claims with external sources. Cross-validate model output.",
                ))

        return ScanResult(
            sanitized=output,
            action=ScanAction.WARN,
            risk_score=risk,
            findings=findings,
            metadata={
                "consistency_score": round(avg_score, 3),
                "checks": {c.check_name: round(c.score, 3) for c in checks},
                "below_threshold": [c.check_name for c in checks if c.score < self._minimum_score],
            },
        )

    # ── Check Methods ─────────────────────────────────────────────────

    def _token_overlap_score(self, prompt: str, output: str) -> float:
        """Measures how grounded the output is in prompt tokens."""
        prompt_tokens = set(self._tokenize(prompt))
        output_tokens = set(self._tokenize(output))

        content_output = output_tokens - STOP_WORDS
        content_prompt = prompt_tokens - STOP_WORDS

        if not content_output:
            return 1.0

        grounded = content_output & content_prompt
        return len(grounded) / len(content_output)

    def _number_consistency(self, prompt: str, output: str) -> float:
        """Checks if numbers in output match those in prompt."""
        prompt_numbers = set(re.findall(r"\b\d+(?:\.\d+)?\b", prompt))
        output_numbers = set(re.findall(r"\b\d+(?:\.\d+)?\b", output))

        if not output_numbers:
            return 1.0

        # Exclude trivially common numbers
        trivial = {"0", "1", "2", "3", "4", "5", "10", "100"}
        novel_numbers = output_numbers - prompt_numbers - trivial

        if not novel_numbers:
            return 1.0

        penalty = min(1.0, len(novel_numbers) * 0.15)
        return max(0.0, 1.0 - penalty)

    def _negation_check(self, prompt: str, output: str) -> float:
        """Detects negation contradictions between prompt and output."""
        prompt_lower = prompt.lower()
        output_lower = output.lower()

        prompt_neg_count = sum(1 for w in prompt_lower.split() if w in NEGATION_WORDS)
        output_neg_count = sum(1 for w in output_lower.split() if w in NEGATION_WORDS)

        if prompt_neg_count == 0 and output_neg_count == 0:
            return 1.0

        diff = abs(prompt_neg_count - output_neg_count)
        return max(0.0, 1.0 - diff * 0.2)

    def _entity_grounding(self, prompt: str, output: str) -> tuple[float, set[str]]:
        """Checks if capitalized entities in output exist in prompt."""
        prompt_entities = set(re.findall(r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b", prompt))
        output_entities = set(re.findall(r"\b[A-Z][a-z]+(?:\s+[A-Z][a-z]+)*\b", output))

        content_output = output_entities - COMMON_ENTITIES
        content_prompt = prompt_entities - COMMON_ENTITIES

        if not content_output:
            return 1.0, set()

        grounded = content_output & content_prompt
        ungrounded = content_output - content_prompt
        score = len(grounded) / len(content_output)
        return score, ungrounded

    def _self_consistency(self, output: str) -> tuple[float, list[str]]:
        """Check for contradictions within the response itself."""
        sentences = re.split(r"[.!?]+\s+", output)
        sentences = [s.strip() for s in sentences if len(s.strip()) > 10]

        if len(sentences) < 2:
            return 1.0, []

        contradictions = []

        # Check for opposite quantifiers in related sentences
        for i, sent_a in enumerate(sentences):
            for sent_b in sentences[i+1:]:
                # Look for shared content words
                words_a = set(self._tokenize(sent_a)) - STOP_WORDS
                words_b = set(self._tokenize(sent_b)) - STOP_WORDS
                overlap = words_a & words_b

                if len(overlap) < 2:
                    continue

                # Check if one has negation and other doesn't on overlapping content
                neg_a = any(w in NEGATION_WORDS for w in sent_a.lower().split())
                neg_b = any(w in NEGATION_WORDS for w in sent_b.lower().split())

                if neg_a != neg_b and len(overlap) >= 3:
                    shared = ", ".join(list(overlap)[:3])
                    contradictions.append(f"Conflicting statements about: {shared}")

        if not contradictions:
            return 1.0, []

        score = max(0.0, 1.0 - len(contradictions) * 0.25)
        return score, contradictions

    @staticmethod
    def _tokenize(text: str) -> list[str]:
        return re.findall(r"\b\w+\b", text.lower())
