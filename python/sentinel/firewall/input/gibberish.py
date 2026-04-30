"""
Eresus Sentinel — Gibberish / Noise Detection Scanner.

Detects nonsensical, garbled, or garbage input that may indicate:
  - Automated fuzzing attempts
  - Encoding-based bypass attacks
  - Adversarial suffix attacks (like GCG)
  - Random token generation attacks
"""

from __future__ import annotations

import logging
import math
import string

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import InputScanner, ScanAction, ScanResult

logger = logging.getLogger(__name__)

VOWELS = set("aeiouAEIOUàáâãäåèéêëìíîïòóôõöùúûüÿ")
CONSONANTS = set(string.ascii_letters) - VOWELS


def _entropy(text: str) -> float:
    """Calculate Shannon entropy of text."""
    if not text:
        return 0.0
    freq: dict[str, int] = {}
    for ch in text:
        freq[ch] = freq.get(ch, 0) + 1
    length = len(text)
    return -sum((c / length) * math.log2(c / length) for c in freq.values())


def _vowel_ratio(text: str) -> float:
    """Ratio of vowels to alphabetic characters."""
    alpha = [c for c in text if c.isalpha()]
    if not alpha:
        return 0.0
    return sum(1 for c in alpha if c in VOWELS) / len(alpha)


def _repeated_char_ratio(text: str) -> float:
    """Ratio of repeated consecutive characters."""
    if len(text) < 2:
        return 0.0
    repeats = sum(1 for i in range(1, len(text)) if text[i] == text[i-1])
    return repeats / (len(text) - 1)


def _word_length_variance(text: str) -> float:
    """Variance of word lengths — gibberish tends to have extreme variance."""
    words = text.split()
    if len(words) < 2:
        return 0.0
    lengths = [len(w) for w in words]
    mean = sum(lengths) / len(lengths)
    return sum((l - mean) ** 2 for l in lengths) / len(lengths)


def _special_char_ratio(text: str) -> float:
    """Ratio of non-alphanumeric, non-whitespace characters."""
    if not text:
        return 0.0
    special = sum(1 for c in text if not c.isalnum() and not c.isspace())
    return special / len(text)


def _consecutive_consonant_max(text: str) -> int:
    """Maximum consecutive consonant run length."""
    max_run = 0
    current = 0
    for c in text:
        if c.lower() in CONSONANTS:
            current += 1
            max_run = max(max_run, current)
        else:
            current = 0
    return max_run


class GibberishScanner(InputScanner):
    """
    Detects gibberish/noise input using statistical analysis.

    Analyses Shannon entropy, vowel ratio, word length variance,
    special character density, and consecutive consonant runs to
    identify non-natural-language input.
    """

    def __init__(self, threshold: float = 0.7):
        self._threshold = threshold

    def scan(self, prompt: str) -> ScanResult:
        if not prompt or len(prompt.strip()) < 10:
            return ScanResult(sanitized=prompt, action=ScanAction.PASS, risk_score=0.0)

        scores: list[float] = []

        entropy = _entropy(prompt)
        if entropy > 5.5:
            scores.append(0.8)
        elif entropy > 4.5:
            scores.append(0.4)
        else:
            scores.append(0.0)

        vr = _vowel_ratio(prompt)
        if vr < 0.15 or vr > 0.65:
            scores.append(0.7)
        elif vr < 0.25 or vr > 0.55:
            scores.append(0.3)
        else:
            scores.append(0.0)

        scr = _special_char_ratio(prompt)
        if scr > 0.4:
            scores.append(0.9)
        elif scr > 0.25:
            scores.append(0.5)
        else:
            scores.append(0.0)

        cc = _consecutive_consonant_max(prompt)
        if cc > 8:
            scores.append(0.8)
        elif cc > 5:
            scores.append(0.4)
        else:
            scores.append(0.0)

        rr = _repeated_char_ratio(prompt)
        if rr > 0.3:
            scores.append(0.7)
        elif rr > 0.15:
            scores.append(0.3)
        else:
            scores.append(0.0)

        wlv = _word_length_variance(prompt)
        if wlv > 100:
            scores.append(0.6)
        elif wlv > 50:
            scores.append(0.3)
        else:
            scores.append(0.0)

        final_score = sum(scores) / len(scores) if scores else 0.0

        if final_score >= self._threshold:
            finding = Finding.firewall_input(
                rule_id="FIREWALL-INPUT-080",
                title="Gibberish / adversarial noise detected",
                description=(
                    f"Input appears to be gibberish or adversarial noise "
                    f"(score: {final_score:.2f}). High entropy: {entropy:.1f}, "
                    f"vowel ratio: {vr:.2f}, special chars: {scr:.2f}, "
                    f"max consonant run: {cc}"
                ),
                severity=Severity.MEDIUM,
                confidence=final_score,
                target="<prompt>",
                evidence=(
                    f"Entropy={entropy:.2f}, VowelRatio={vr:.2f}, "
                    f"SpecialChars={scr:.2f}, MaxConsonants={cc}, "
                    f"RepeatedChars={rr:.2f}, WordLenVar={wlv:.1f}"
                ),
                cwe_ids=["CWE-20"],
                tags=["owasp:llm01", "category:gibberish"],
                remediation="Reject non-natural-language input.",
            )
            return ScanResult(
                sanitized=prompt,
                action=ScanAction.BLOCK if final_score > 0.85 else ScanAction.WARN,
                risk_score=final_score,
                findings=[finding],
            )

        return ScanResult(sanitized=prompt, action=ScanAction.PASS, risk_score=final_score)
