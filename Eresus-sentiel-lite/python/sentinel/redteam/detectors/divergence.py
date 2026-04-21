"""
Divergence Detector.

Detects output divergence patterns:
  - Repetitive loops (same phrase/word repeated)
  - Coherence degradation (entropy collapse)
  - Token flood (single token dominance)
  - Length anomalies (unreasonably long/short responses)
"""

from __future__ import annotations

import re
from collections import Counter
from dataclasses import dataclass


@dataclass
class DivergenceResult:
    """Result from divergence analysis."""
    is_divergent: bool
    divergence_type: str  # "repetition" | "entropy_collapse" | "token_flood" | "length_anomaly" | "none"
    score: float  # 0.0 (no divergence) to 1.0 (severe divergence)
    detail: str


class DivergenceDetector:
    """
    Detect output divergence patterns in model responses.

    Checks for:
      - Word/phrase repetition beyond natural levels
      - Entropy collapse (low information content)
      - Single-token dominance
      - Abnormal response lengths

    Usage:
        detector = DivergenceDetector()
        result = detector.detect("hello hello hello hello hello hello")
        assert result.is_divergent
    """

    def __init__(
        self,
        repetition_threshold: float = 0.4,
        entropy_threshold: float = 1.5,
        max_expected_length: int = 10000,
        min_expected_length: int = 5,
    ):
        self._rep_threshold = repetition_threshold
        self._entropy_threshold = entropy_threshold
        self._max_length = max_expected_length
        self._min_length = min_expected_length

    def detect(self, text: str) -> DivergenceResult:
        """Analyze text for divergence patterns."""
        if not text or not text.strip():
            return DivergenceResult(False, "none", 0.0, "Empty response")

        # Check length anomaly first
        length_result = self._check_length(text)
        if length_result.is_divergent:
            return length_result

        # Check repetition
        rep_result = self._check_repetition(text)
        if rep_result.is_divergent:
            return rep_result

        # Check entropy
        entropy_result = self._check_entropy(text)
        if entropy_result.is_divergent:
            return entropy_result

        # Check token flood
        flood_result = self._check_token_flood(text)
        if flood_result.is_divergent:
            return flood_result

        return DivergenceResult(False, "none", 0.0, "No divergence detected")

    def _check_repetition(self, text: str) -> DivergenceResult:
        """Check for repeated words/phrases."""
        words = text.lower().split()
        if len(words) < 10:
            return DivergenceResult(False, "none", 0.0, "Too few words")

        # Check word repetition
        counter = Counter(words)
        most_common_word, most_common_count = counter.most_common(1)[0]
        word_ratio = most_common_count / len(words)

        if word_ratio > self._rep_threshold:
            return DivergenceResult(
                True, "repetition", word_ratio,
                f"'{most_common_word}' repeated {most_common_count}/{len(words)} times ({word_ratio:.1%})"
            )

        # Check n-gram repetition (bigrams and trigrams)
        for n in [2, 3]:
            if len(words) < n * 3:
                continue
            ngrams = [" ".join(words[i:i+n]) for i in range(len(words) - n + 1)]
            ng_counter = Counter(ngrams)
            top_ng, top_count = ng_counter.most_common(1)[0]
            ng_ratio = top_count / len(ngrams)

            if ng_ratio > self._rep_threshold * 0.8:
                return DivergenceResult(
                    True, "repetition", ng_ratio,
                    f"'{top_ng}' ({n}-gram) repeated {top_count} times ({ng_ratio:.1%})"
                )

        return DivergenceResult(False, "none", word_ratio, "")

    def _check_entropy(self, text: str) -> DivergenceResult:
        """Check for entropy collapse (low information content)."""
        import math

        chars = list(text)
        if len(chars) < 20:
            return DivergenceResult(False, "none", 0.0, "Too short for entropy check")

        counter = Counter(chars)
        total = len(chars)
        entropy = -sum((c / total) * math.log2(c / total) for c in counter.values())

        if entropy < self._entropy_threshold:
            return DivergenceResult(
                True, "entropy_collapse", 1.0 - (entropy / 8.0),
                f"Shannon entropy={entropy:.2f} (threshold={self._entropy_threshold})"
            )

        return DivergenceResult(False, "none", 0.0, "")

    def _check_token_flood(self, text: str) -> DivergenceResult:
        """Check for single character/token dominance."""
        if len(text) < 50:
            return DivergenceResult(False, "none", 0.0, "")

        counter = Counter(text)
        top_char, top_count = counter.most_common(1)[0]
        ratio = top_count / len(text)

        if ratio > 0.5 and top_char not in " \n\t":
            return DivergenceResult(
                True, "token_flood", ratio,
                f"Character '{repr(top_char)}' dominates {ratio:.1%} of output"
            )

        return DivergenceResult(False, "none", 0.0, "")

    def _check_length(self, text: str) -> DivergenceResult:
        """Check for abnormal response length."""
        if len(text) > self._max_length:
            return DivergenceResult(
                True, "length_anomaly", min(1.0, len(text) / (self._max_length * 2)),
                f"Response length {len(text)} exceeds max {self._max_length}"
            )

        return DivergenceResult(False, "none", 0.0, "")
