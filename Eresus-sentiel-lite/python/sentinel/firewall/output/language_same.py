"""
Output-side language consistency scanner — verifies response matches prompt language.

Production-grade features:
  - Unicode script-based language family detection (no ML dependency)
  - 15 language families supported
  - Bigram frequency analysis for Latin-script languages
  - Mixed-language detection
  - Code block exclusion
  - Confidence scoring
"""

from __future__ import annotations

import logging
import re
from collections import Counter
from dataclasses import dataclass

logger = logging.getLogger(__name__)

# Unicode block ranges for script detection
_SCRIPT_RANGES: dict[str, list[tuple[int, int]]] = {
    "latin": [(0x0041, 0x024F)],
    "cyrillic": [(0x0400, 0x04FF), (0x0500, 0x052F)],
    "arabic": [(0x0600, 0x06FF), (0x0750, 0x077F), (0x08A0, 0x08FF)],
    "hebrew": [(0x0590, 0x05FF)],
    "devanagari": [(0x0900, 0x097F)],
    "bengali": [(0x0980, 0x09FF)],
    "thai": [(0x0E00, 0x0E7F)],
    "cjk": [(0x4E00, 0x9FFF), (0x3400, 0x4DBF), (0x2E80, 0x2EFF)],
    "hangul": [(0xAC00, 0xD7AF), (0x1100, 0x11FF)],
    "hiragana": [(0x3040, 0x309F)],
    "katakana": [(0x30A0, 0x30FF)],
    "greek": [(0x0370, 0x03FF)],
    "georgian": [(0x10A0, 0x10FF)],
    "armenian": [(0x0530, 0x058F)],
    "ethiopic": [(0x1200, 0x137F)],
}

# Common bigrams per Latin-script language (top 10)
_LATIN_BIGRAMS: dict[str, set[str]] = {
    "english": {"th", "he", "in", "er", "an", "re", "on", "at", "en", "nd", "ti", "es", "or", "te", "of", "ed", "is", "it", "al", "ar"},
    "spanish": {"de", "en", "el", "es", "la", "er", "on", "an", "re", "al", "te", "os", "as", "ci", "ta", "se", "ra", "io", "ar", "ue"},
    "french": {"es", "le", "de", "en", "re", "on", "nt", "er", "an", "te", "ou", "se", "ai", "qu", "la", "it", "ti", "et", "ne", "co"},
    "german": {"en", "er", "ch", "de", "ei", "in", "nd", "ie", "ge", "te", "be", "un", "an", "st", "es", "di", "he", "re", "au", "se"},
    "portuguese": {"de", "os", "as", "er", "es", "do", "da", "em", "ar", "an", "co", "ra", "en", "al", "te", "re", "on", "se", "ta", "or"},
    "italian": {"er", "re", "io", "an", "on", "en", "in", "la", "el", "to", "di", "co", "al", "de", "no", "te", "ti", "ne", "ta", "le"},
    "turkish": {"la", "le", "ar", "an", "er", "in", "de", "en", "ir", "da", "ak", "ik", "al", "ya", "bi", "ri", "il", "el", "li", "di"},
}

# Pattern to strip code blocks before analysis
_CODE_BLOCK = re.compile(r"```[\s\S]*?```", re.MULTILINE)
_INLINE_CODE = re.compile(r"`[^`]+`")


@dataclass
class LanguageDetection:
    """Language detection result for a piece of text."""
    primary_script: str
    primary_language: str
    confidence: float
    script_distribution: dict[str, float]
    is_mixed: bool


@dataclass
class LanguageSameResult:
    """Complete language consistency check result."""
    is_consistent: bool
    prompt_language: LanguageDetection
    response_language: LanguageDetection
    mismatch_detail: str
    risk_score: float


class LanguageSameOutputScanner:
    """
    Verifies response language matches prompt language.

    Detection methods:
      1. Unicode script analysis (identifies writing system)
      2. Bigram frequency for Latin-script disambiguation
      3. Mixed-language detection

    Catches language-switching attacks where a response
    switches to a different language to bypass content filters.

    Usage:
        scanner = LanguageSameOutputScanner()
        result = scanner.scan("What is AI?", "AI 是人工智能的缩写")
        assert not result.is_consistent  # English prompt, Chinese response
    """

    def __init__(self, tolerance: float = 0.3):
        self._tolerance = tolerance

    def scan(self, prompt: str, output: str) -> LanguageSameResult:
        """Check if response language matches prompt language."""
        # Strip code blocks from analysis
        clean_prompt = self._strip_code(prompt)
        clean_output = self._strip_code(output)

        if not clean_prompt.strip() or not clean_output.strip():
            return LanguageSameResult(
                is_consistent=True,
                prompt_language=LanguageDetection("unknown", "unknown", 0.0, {}, False),
                response_language=LanguageDetection("unknown", "unknown", 0.0, {}, False),
                mismatch_detail="Insufficient text for analysis",
                risk_score=0.0,
            )

        prompt_lang = self._detect_language(clean_prompt)
        response_lang = self._detect_language(clean_output)

        # Compare primary scripts
        is_consistent = True
        mismatch_detail = "Languages match"
        risk = 0.0

        if prompt_lang.primary_script != response_lang.primary_script:
            if prompt_lang.primary_script != "unknown" and response_lang.primary_script != "unknown":
                is_consistent = False
                mismatch_detail = (
                    f"Script mismatch: prompt={prompt_lang.primary_script} "
                    f"({prompt_lang.primary_language}), "
                    f"response={response_lang.primary_script} "
                    f"({response_lang.primary_language})"
                )
                risk = 0.7

        # For Latin-script, also check sublanguage
        elif prompt_lang.primary_script == "latin" and prompt_lang.primary_language != response_lang.primary_language:
            if prompt_lang.confidence > 0.5 and response_lang.confidence > 0.5:
                is_consistent = False
                mismatch_detail = (
                    f"Language mismatch: prompt={prompt_lang.primary_language}, "
                    f"response={response_lang.primary_language}"
                )
                risk = 0.4

        # Mixed language in response is suspicious
        if response_lang.is_mixed and not prompt_lang.is_mixed:
            risk = max(risk, 0.3)
            if is_consistent:
                mismatch_detail = "Response contains mixed languages"

        return LanguageSameResult(
            is_consistent=is_consistent,
            prompt_language=prompt_lang,
            response_language=response_lang,
            mismatch_detail=mismatch_detail,
            risk_score=round(risk, 4),
        )

    def _detect_language(self, text: str) -> LanguageDetection:
        """Detect language from text."""
        # Script analysis
        script_counts: Counter[str] = Counter()
        alpha_count = 0

        for char in text:
            cp = ord(char)
            for script, ranges in _SCRIPT_RANGES.items():
                for lo, hi in ranges:
                    if lo <= cp <= hi:
                        script_counts[script] += 1
                        alpha_count += 1
                        break

        if alpha_count == 0:
            return LanguageDetection("unknown", "unknown", 0.0, {}, False)

        # Script distribution
        distribution = {s: c / alpha_count for s, c in script_counts.items()}
        primary_script = script_counts.most_common(1)[0][0] if script_counts else "unknown"
        primary_ratio = script_counts.most_common(1)[0][1] / alpha_count if script_counts else 0.0

        # Mixed language detection
        is_mixed = len([s for s, r in distribution.items() if r > 0.1]) > 1

        # Latin-script sublanguage detection via bigrams
        primary_language = primary_script
        confidence = primary_ratio

        if primary_script == "latin":
            lang, conf = self._detect_latin_language(text)
            primary_language = lang
            confidence = conf
        elif primary_script == "cjk":
            primary_language = "chinese"
        elif primary_script in ("hiragana", "katakana"):
            primary_language = "japanese"
        elif primary_script == "hangul":
            primary_language = "korean"

        return LanguageDetection(
            primary_script=primary_script,
            primary_language=primary_language,
            confidence=round(confidence, 4),
            script_distribution={k: round(v, 4) for k, v in distribution.items()},
            is_mixed=is_mixed,
        )

    @staticmethod
    def _detect_latin_language(text: str) -> tuple[str, float]:
        """Detect specific language within Latin script using bigrams."""
        clean = re.sub(r"[^a-z]", "", text.lower())
        if len(clean) < 20:
            return "english", 0.3  # Default assumption

        # Extract bigrams
        bigrams = set()
        for i in range(len(clean) - 1):
            bigrams.add(clean[i:i+2])

        # Score against each language's expected bigrams
        best_lang = "english"
        best_score = 0.0

        for lang, expected in _LATIN_BIGRAMS.items():
            overlap = len(bigrams & expected) / max(len(expected), 1)
            if overlap > best_score:
                best_score = overlap
                best_lang = lang

        return best_lang, min(1.0, best_score * 2)

    @staticmethod
    def _strip_code(text: str) -> str:
        """Remove code blocks from text."""
        text = _CODE_BLOCK.sub("", text)
        text = _INLINE_CODE.sub("", text)
        return text
