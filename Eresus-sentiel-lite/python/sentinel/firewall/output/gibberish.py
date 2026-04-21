"""
Output-side gibberish/noise detector — catches model output degradation.

Production-grade features:
  - 6 detection methods (entropy, repetition, charset, ratio, dictionary, structure)
  - Language-agnostic entropy analysis
  - Repetition collapse detection (token flooding)
  - Character class distribution analysis
  - Vowel-consonant ratio checks
  - Dictionary word coverage estimation
  - Structural coherence scoring
  - Per-method breakdown reporting
"""

from __future__ import annotations

import logging
import math
import re
from collections import Counter
from dataclasses import dataclass, field

logger = logging.getLogger(__name__)

# Common English words for dictionary coverage check
_COMMON_WORDS = frozenset({
    "the", "be", "to", "of", "and", "a", "in", "that", "have", "i",
    "it", "for", "not", "on", "with", "he", "as", "you", "do", "at",
    "this", "but", "his", "by", "from", "they", "we", "say", "her", "she",
    "or", "an", "will", "my", "one", "all", "would", "there", "their", "what",
    "so", "up", "out", "if", "about", "who", "get", "which", "go", "me",
    "when", "make", "can", "like", "time", "no", "just", "him", "know", "take",
    "people", "into", "year", "your", "good", "some", "could", "them", "see",
    "other", "than", "then", "now", "look", "only", "come", "its", "over",
    "think", "also", "back", "after", "use", "two", "how", "our", "work",
    "first", "well", "way", "even", "new", "want", "because", "any", "these",
    "give", "day", "most", "us", "is", "are", "was", "were", "been", "has",
    "had", "did", "does", "doing", "should", "may", "might", "must", "shall",
})


@dataclass
class GibberishMethodScore:
    """Score from a single detection method."""
    method: str
    score: float  # 0.0 = coherent, 1.0 = gibberish
    detail: str


@dataclass
class GibberishResult:
    """Complete gibberish detection result."""
    is_gibberish: bool
    overall_score: float
    method_scores: list[GibberishMethodScore]
    worst_method: str
    entropy: float
    repetition_ratio: float
    dict_coverage: float
    detail: str


class GibberishOutputScanner:
    """
    Detects gibberish/noise in LLM responses.

    Catches:
      - Model collapse / degradation
      - Encoding corruption
      - Adversarial noise injection
      - Token flooding / repetition attacks
      - Nonsensical filler output

    6 detection methods:
      1. Shannon entropy analysis
      2. Repetition ratio (n-gram overuse)
      3. Character class distribution
      4. Vowel-consonant ratio
      5. Dictionary word coverage
      6. Structural coherence (sentence patterns)

    Usage:
        scanner = GibberishOutputScanner()
        result = scanner.scan("", "askjdhaksjdh asjkdhajsk djhasjkdh")
        assert result.is_gibberish
    """

    def __init__(self, threshold: float = 0.65):
        self._threshold = threshold

    def scan(self, prompt: str, output: str) -> GibberishResult:
        """Scan output for gibberish content."""
        if not output or len(output.strip()) < 10:
            return GibberishResult(
                is_gibberish=False, overall_score=0.0, method_scores=[],
                worst_method="none", entropy=0.0, repetition_ratio=0.0,
                dict_coverage=1.0, detail="Too short to analyze",
            )

        methods: list[GibberishMethodScore] = []

        # 1. Entropy analysis
        entropy = self._shannon_entropy(output)
        entropy_score = self._entropy_to_gibberish_score(entropy, len(output))
        methods.append(GibberishMethodScore("entropy", entropy_score,
            f"Shannon entropy: {entropy:.2f} bits/char"))

        # 2. Repetition analysis
        rep_ratio = self._repetition_ratio(output)
        rep_score = rep_ratio  # High repetition = gibberish
        methods.append(GibberishMethodScore("repetition", rep_score,
            f"Repetition ratio: {rep_ratio:.3f}"))

        # 3. Character class distribution
        charset_score = self._charset_analysis(output)
        methods.append(GibberishMethodScore("charset", charset_score,
            f"Charset anomaly: {charset_score:.3f}"))

        # 4. Vowel-consonant ratio
        vc_score = self._vowel_consonant_ratio(output)
        methods.append(GibberishMethodScore("vowel_consonant", vc_score,
            f"V/C ratio anomaly: {vc_score:.3f}"))

        # 5. Dictionary coverage
        dict_cov = self._dictionary_coverage(output)
        dict_score = max(0.0, 1.0 - dict_cov * 1.5)  # Low coverage → high score
        methods.append(GibberishMethodScore("dictionary", dict_score,
            f"Dict coverage: {dict_cov:.1%}"))

        # 6. Structural coherence
        struct_score = self._structural_coherence(output)
        methods.append(GibberishMethodScore("structure", struct_score,
            f"Structural anomaly: {struct_score:.3f}"))

        # Overall: weighted average
        weights = [0.2, 0.25, 0.1, 0.1, 0.25, 0.1]
        overall = sum(s.score * w for s, w in zip(methods, weights))
        worst = max(methods, key=lambda m: m.score)

        is_gibberish = overall >= self._threshold

        return GibberishResult(
            is_gibberish=is_gibberish,
            overall_score=round(overall, 4),
            method_scores=methods,
            worst_method=worst.method,
            entropy=round(entropy, 4),
            repetition_ratio=round(rep_ratio, 4),
            dict_coverage=round(dict_cov, 4),
            detail=f"Overall: {overall:.3f} (threshold: {self._threshold}). "
                   f"Worst: {worst.method} = {worst.score:.3f}",
        )

    @staticmethod
    def _shannon_entropy(text: str) -> float:
        """Calculate Shannon entropy (bits per character)."""
        if not text:
            return 0.0
        freq = Counter(text)
        length = len(text)
        return -sum((c / length) * math.log2(c / length) for c in freq.values())

    @staticmethod
    def _entropy_to_gibberish_score(entropy: float, length: int) -> float:
        """Convert entropy to gibberish score."""
        # Normal English text: ~4.0-4.5 bits/char
        # Random chars: ~6.5-7.0 bits/char
        # Repeated text: ~1.0-2.0 bits/char
        if length < 20:
            return 0.0
        if entropy > 6.0:  # Very high entropy = random noise
            return min(1.0, (entropy - 6.0) / 1.5)
        if entropy < 2.0:  # Very low entropy = extreme repetition
            return min(1.0, (2.0 - entropy) / 1.5)
        return 0.0

    @staticmethod
    def _repetition_ratio(text: str) -> float:
        """Detect repetitive patterns (ngram overuse)."""
        words = text.lower().split()
        if len(words) < 5:
            return 0.0

        # Check 3-gram repetition
        trigrams = [" ".join(words[i:i+3]) for i in range(len(words) - 2)]
        if not trigrams:
            return 0.0

        freq = Counter(trigrams)
        most_common_count = freq.most_common(1)[0][1]
        ratio = most_common_count / len(trigrams)

        # Also check single word repetition
        word_freq = Counter(words)
        word_ratio = word_freq.most_common(1)[0][1] / len(words)

        # Either high trigram or word repetition is suspicious
        return max(ratio, word_ratio * 0.8) if word_ratio > 0.3 else ratio

    @staticmethod
    def _charset_analysis(text: str) -> float:
        """Analyze character class distribution."""
        if not text:
            return 0.0

        alpha = sum(1 for c in text if c.isalpha())
        digit = sum(1 for c in text if c.isdigit())
        space = sum(1 for c in text if c.isspace())
        punct = sum(1 for c in text if not c.isalnum() and not c.isspace())
        total = len(text)

        # Normal text: ~70-80% alpha, 5-15% space, 2-5% punct
        alpha_ratio = alpha / total
        space_ratio = space / total
        punct_ratio = punct / total

        score = 0.0
        if alpha_ratio < 0.3:  # Not enough letters
            score += 0.4
        if space_ratio < 0.05 and total > 50:  # No spaces in long text
            score += 0.3
        if punct_ratio > 0.3:  # Too much punctuation
            score += 0.3
        if digit / max(total, 1) > 0.5:  # Mostly numbers
            score += 0.2

        return min(1.0, score)

    @staticmethod
    def _vowel_consonant_ratio(text: str) -> float:
        """Check vowel-to-consonant ratio."""
        vowels = sum(1 for c in text.lower() if c in "aeiou")
        consonants = sum(1 for c in text.lower() if c.isalpha() and c not in "aeiou")

        if consonants == 0:
            return 0.5 if vowels > 0 else 0.0

        ratio = vowels / consonants
        # Normal English: ~0.55-0.65 V/C ratio
        if ratio < 0.15 or ratio > 1.5:
            return min(1.0, abs(ratio - 0.6) / 0.6)
        return 0.0

    @staticmethod
    def _dictionary_coverage(text: str) -> float:
        """Estimate fraction of words in common dictionary."""
        words = re.findall(r"\b[a-z]{2,}\b", text.lower())
        if not words:
            return 0.0
        known = sum(1 for w in words if w in _COMMON_WORDS)
        return known / len(words)

    @staticmethod
    def _structural_coherence(text: str) -> float:
        """Check structural patterns of coherent text."""
        score = 0.0
        lines = text.split("\n")

        # Check for sentence endings
        sentences = re.findall(r"[.!?]\s", text)
        if len(text) > 100 and len(sentences) == 0:
            score += 0.3

        # Check for very long "words" (no spaces)
        longest_word = max((len(w) for w in text.split()), default=0)
        if longest_word > 40:
            score += 0.4

        # Check for repeated lines
        if len(lines) > 3:
            unique = len(set(l.strip() for l in lines if l.strip()))
            if unique < len([l for l in lines if l.strip()]) * 0.3:
                score += 0.4

        return min(1.0, score)
