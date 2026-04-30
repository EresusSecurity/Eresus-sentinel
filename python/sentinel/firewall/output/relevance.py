"""
Eresus Sentinel — Relevance Scanner (Output).

Checks if the LLM response is relevant to the original prompt.
Detects:
  - Off-topic responses (model distraction/manipulation)
  - Injection-induced topic drift
  - System prompt leakage disguised as answers

Uses lightweight keyword/n-gram overlap scoring.
"""

from __future__ import annotations

import logging
import re

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import OutputScanner, ScanAction, ScanResult

logger = logging.getLogger(__name__)

STOP_WORDS = frozenset({
    "a", "an", "the", "is", "are", "was", "were", "be", "been", "being",
    "have", "has", "had", "do", "does", "did", "will", "would", "could",
    "should", "may", "might", "shall", "can", "to", "of", "in", "for",
    "on", "with", "at", "by", "from", "as", "into", "through", "during",
    "before", "after", "above", "below", "between", "under", "again",
    "further", "then", "once", "here", "there", "when", "where", "why",
    "how", "all", "both", "each", "few", "more", "most", "other", "some",
    "such", "no", "nor", "not", "only", "own", "same", "so", "than",
    "too", "very", "just", "don", "now", "and", "but", "or", "if",
    "what", "which", "who", "whom", "this", "that", "these", "those",
    "i", "me", "my", "we", "our", "you", "your", "he", "she", "it",
    "they", "them", "his", "her", "its", "us",
})


def _extract_keywords(text: str) -> set[str]:
    """Extract meaningful keywords from text."""
    words = re.findall(r"\b\w{3,}\b", text.lower())
    return {w for w in words if w not in STOP_WORDS}


def _ngrams(text: str, n: int = 2) -> set[tuple[str, ...]]:
    """Extract n-grams from text."""
    words = re.findall(r"\b\w{3,}\b", text.lower())
    words = [w for w in words if w not in STOP_WORDS]
    if len(words) < n:
        return set()
    return {tuple(words[i:i+n]) for i in range(len(words) - n + 1)}


def _jaccard_similarity(set_a: set, set_b: set) -> float:
    """Jaccard similarity between two sets."""
    if not set_a or not set_b:
        return 0.0
    intersection = set_a & set_b
    union = set_a | set_b
    return len(intersection) / len(union) if union else 0.0


class RelevanceScanner(OutputScanner):
    """
    Checks response relevance to the original prompt.

    Uses keyword overlap and bi-gram similarity to detect
    off-topic or manipulated responses.
    """

    def __init__(self, threshold: float = 0.1):
        """
        Args:
            threshold: Minimum relevance score (below = off-topic).
        """
        self._threshold = threshold

    def scan(self, prompt: str, output: str) -> ScanResult:
        if not prompt or not output:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        if len(prompt.strip()) < 10 or len(output.strip()) < 20:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        prompt_kw = _extract_keywords(prompt)
        output_kw = _extract_keywords(output)

        kw_similarity = _jaccard_similarity(prompt_kw, output_kw)
        ngram_similarity = _jaccard_similarity(
            _ngrams(prompt), _ngrams(output)
        )

        relevance = (kw_similarity * 0.7 + ngram_similarity * 0.3)

        if relevance < self._threshold:
            finding = Finding.firewall_output(
                rule_id="FIREWALL-OUTPUT-080",
                title=f"Low relevance score: {relevance:.2f}",
                description=(
                    f"Response appears off-topic relative to the prompt. "
                    f"Keyword overlap: {kw_similarity:.2f}, "
                    f"N-gram overlap: {ngram_similarity:.2f}. "
                    f"This may indicate injection-induced topic drift."
                ),
                severity=Severity.MEDIUM,
                confidence=max(0.5, 1 - relevance),
                target="<response>",
                evidence=(
                    f"Relevance={relevance:.3f}, "
                    f"Keywords={kw_similarity:.3f}, "
                    f"Ngrams={ngram_similarity:.3f}"
                ),
                cwe_ids=["CWE-20"],
                tags=["owasp:llm02", "category:relevance"],
                remediation="Response seems unrelated to the prompt.",
            )
            return ScanResult(
                sanitized=output,
                action=ScanAction.WARN,
                risk_score=1 - relevance,
                findings=[finding],
            )

        return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)
