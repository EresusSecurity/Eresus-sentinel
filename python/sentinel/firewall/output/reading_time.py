"""
Eresus Sentinel — Reading Time / Response Length Scanner (Output).

Production-grade response length enforcement with:
  - Word count limits
  - Reading time estimation (adjustable WPM)
  - Character count limits
  - Sentence count limits
  - Paragraph count limits
  - Code block detection (excluded from reading time)
  - Truncation mode (auto-trim to limit)
  - Cost amplification detection
  - Repetition detection in long outputs
  - Detailed length breakdown
"""

from __future__ import annotations

import logging
import re

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import OutputScanner, ScanResult, ScanAction

logger = logging.getLogger(__name__)

# Reading speeds for different content types
WPM_NORMAL = 200
WPM_TECHNICAL = 150
WPM_CASUAL = 250

CODE_BLOCK_PATTERN = re.compile(r"```[\s\S]*?```", re.MULTILINE)
SENTENCE_PATTERN = re.compile(r"[.!?]+\s+|\n")
PARAGRAPH_PATTERN = re.compile(r"\n\s*\n")
REPETITION_PATTERN = re.compile(r"(.{20,}?)\1{2,}", re.DOTALL)


class ReadingTimeScanner(OutputScanner):
    """
    Enforces maximum reading time, word count, and structural limits.

    Multi-dimensional length checking:
    - Word count / reading time
    - Character count
    - Sentence count
    - Paragraph count
    - Code block ratio

    Detects:
    - Excessively long responses (cost amplification)
    - Information dumping (over-disclosure)
    - Context exhaustion of downstream consumers
    - Repetitive content in long outputs
    """

    def __init__(
        self,
        max_words: int = 0,
        max_reading_minutes: float = 5.0,
        max_characters: int = 0,
        max_sentences: int = 0,
        max_paragraphs: int = 0,
        wpm: int = WPM_NORMAL,
        truncate: bool = False,
        check_repetition: bool = True,
    ):
        """
        Args:
            max_words: Maximum allowed words (0 = use reading time).
            max_reading_minutes: Maximum reading time in minutes.
            max_characters: Maximum character count (0 = disabled).
            max_sentences: Maximum sentence count (0 = disabled).
            max_paragraphs: Maximum paragraph count (0 = disabled).
            wpm: Words per minute for reading time calculation.
            truncate: Auto-truncate to word limit (vs warn only).
            check_repetition: Detect repetitive segments in long outputs.
        """
        self._wpm = wpm
        self._max_words = max_words or int(max_reading_minutes * wpm)
        self._max_minutes = max_reading_minutes
        self._max_characters = max_characters
        self._max_sentences = max_sentences
        self._max_paragraphs = max_paragraphs
        self._truncate = truncate
        self._check_repetition = check_repetition

    def scan(self, prompt: str, output: str) -> ScanResult:
        if not output:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        findings = []

        # Separate code blocks from prose
        code_blocks = CODE_BLOCK_PATTERN.findall(output)
        prose = CODE_BLOCK_PATTERN.sub("", output)

        # Word count (prose only, excl code blocks)
        words = prose.split()
        word_count = len(words)
        reading_minutes = word_count / self._wpm

        # Total characters
        char_count = len(output)

        # Sentence count
        sentences = [s.strip() for s in SENTENCE_PATTERN.split(prose) if s.strip()]
        sentence_count = len(sentences)

        # Paragraph count
        paragraphs = [p.strip() for p in PARAGRAPH_PATTERN.split(output) if p.strip()]
        paragraph_count = len(paragraphs)

        # Code ratio
        code_chars = sum(len(b) for b in code_blocks)
        code_ratio = code_chars / max(char_count, 1)

        # ── Check: word count ────────────────────────────────────────
        if word_count > self._max_words:
            excess_ratio = word_count / self._max_words
            severity = Severity.MEDIUM if excess_ratio > 2.0 else Severity.LOW
            findings.append(Finding.firewall_output(
                rule_id="FIREWALL-OUTPUT-100",
                title=f"Response too long: {word_count} words ({reading_minutes:.1f} min)",
                description=(
                    f"Response contains {word_count} words "
                    f"(~{reading_minutes:.1f} min reading time), "
                    f"exceeding the limit of {self._max_words} words "
                    f"(~{self._max_minutes:.1f} min). "
                    f"Excess ratio: {excess_ratio:.1f}x."
                ),
                severity=severity,
                confidence=0.95,
                target="<response>",
                evidence=(
                    f"Words: {word_count}, Limit: {self._max_words}, "
                    f"Ratio: {excess_ratio:.1f}x, "
                    f"Reading time: {reading_minutes:.1f} min"
                ),
                cwe_ids=["CWE-400"],
                tags=["owasp:llm04", "category:response-length"],
                remediation="Request a more concise response or increase word limit.",
            ))

        # ── Check: character count ───────────────────────────────────
        if self._max_characters > 0 and char_count > self._max_characters:
            findings.append(Finding.firewall_output(
                rule_id="FIREWALL-OUTPUT-101",
                title=f"Response exceeds character limit: {char_count}",
                description=(
                    f"Response is {char_count:,} characters, "
                    f"exceeding limit of {self._max_characters:,}."
                ),
                severity=Severity.LOW,
                confidence=0.95,
                target="<response>",
                evidence=f"Characters: {char_count:,}, Limit: {self._max_characters:,}",
                cwe_ids=["CWE-400"],
                tags=["category:response-length"],
                remediation="Reduce response length.",
            ))

        # ── Check: sentence count ────────────────────────────────────
        if self._max_sentences > 0 and sentence_count > self._max_sentences:
            findings.append(Finding.firewall_output(
                rule_id="FIREWALL-OUTPUT-102",
                title=f"Too many sentences: {sentence_count}",
                description=(
                    f"Response contains {sentence_count} sentences, "
                    f"exceeding limit of {self._max_sentences}."
                ),
                severity=Severity.LOW,
                confidence=0.85,
                target="<response>",
                evidence=f"Sentences: {sentence_count}, Limit: {self._max_sentences}",
                cwe_ids=["CWE-400"],
                tags=["category:response-length"],
                remediation="Reduce sentence count.",
            ))

        # ── Check: paragraph count ───────────────────────────────────
        if self._max_paragraphs > 0 and paragraph_count > self._max_paragraphs:
            findings.append(Finding.firewall_output(
                rule_id="FIREWALL-OUTPUT-103",
                title=f"Too many paragraphs: {paragraph_count}",
                description=(
                    f"Response contains {paragraph_count} paragraphs, "
                    f"exceeding limit of {self._max_paragraphs}."
                ),
                severity=Severity.LOW,
                confidence=0.85,
                target="<response>",
                evidence=f"Paragraphs: {paragraph_count}, Limit: {self._max_paragraphs}",
                cwe_ids=["CWE-400"],
                tags=["category:response-length"],
                remediation="Reduce paragraph count.",
            ))

        # ── Check: repetition ────────────────────────────────────────
        if self._check_repetition and word_count > 100:
            repeats = REPETITION_PATTERN.findall(output)
            if repeats:
                longest = max(repeats, key=len)
                findings.append(Finding.firewall_output(
                    rule_id="FIREWALL-OUTPUT-104",
                    title=f"Repetitive content detected ({len(repeats)} segments)",
                    description=(
                        f"Response contains repeated text segments, "
                        f"possibly indicating model collapse or generation loop. "
                        f"Repeated segment: '{longest[:80]}...'"
                    ),
                    severity=Severity.MEDIUM,
                    confidence=0.8,
                    target="<response>",
                    evidence=f"Repeated segments: {len(repeats)}, Longest: {len(longest)} chars",
                    cwe_ids=["CWE-400", "CWE-835"],
                    tags=["category:repetition", "category:model-collapse"],
                    remediation="Check for generation loops or model degradation.",
                ))

        # ── No issues ────────────────────────────────────────────────
        if not findings:
            return ScanResult(
                sanitized=output,
                action=ScanAction.PASS,
                risk_score=0.0,
                metadata={
                    "word_count": word_count,
                    "reading_minutes": round(reading_minutes, 1),
                    "characters": char_count,
                    "sentences": sentence_count,
                    "paragraphs": paragraph_count,
                    "code_ratio": round(code_ratio, 2),
                },
            )

        # ── Truncation ───────────────────────────────────────────────
        sanitized = output
        if self._truncate and word_count > self._max_words:
            truncated_words = output.split()[:self._max_words]
            sanitized = " ".join(truncated_words) + "\n\n[Response truncated due to length limit]"

        max_risk = max(
            0.5 if f.severity == Severity.MEDIUM else 0.3
            for f in findings
        )

        return ScanResult(
            sanitized=sanitized,
            action=ScanAction.WARN,
            risk_score=min(0.8, max_risk),
            findings=findings,
            metadata={
                "word_count": word_count,
                "reading_minutes": round(reading_minutes, 1),
                "characters": char_count,
                "sentences": sentence_count,
                "paragraphs": paragraph_count,
                "code_ratio": round(code_ratio, 2),
                "code_blocks": len(code_blocks),
                "truncated": self._truncate and word_count > self._max_words,
            },
        )
