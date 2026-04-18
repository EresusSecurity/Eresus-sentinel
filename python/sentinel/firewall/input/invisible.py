"""
Invisible Text Scanner.

Detects invisible/zero-width Unicode characters in prompts that can
be used to obfuscate prompt injection attacks.

Uses unicodedata.category() to detect Cf (Format), Co (Private Use),
and Cn (Unassigned) Unicode categories.
"""

from __future__ import annotations

import logging
import re
import unicodedata
from typing import Optional

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import InputScanner, ScanResult, ScanAction

logger = logging.getLogger(__name__)

# Unicode categories considered invisible/suspicious
# Cf = Format (zero-width joiners, directional marks, etc.)
# Co = Private Use Area (undefined rendering)
# Cn = Unassigned (no defined character)
INVISIBLE_CATEGORIES = {"Cf", "Co", "Cn"}

# Specific characters to always flag
ALWAYS_FLAG = {
    "\u200b",  # Zero-width space
    "\u2060",  # Word joiner
    "\u2061",  # Function application
    "\u2062",  # Invisible times
    "\u2063",  # Invisible separator
    "\u2064",  # Invisible plus
    "\ufffe",  # Not a character
    "\uffff",  # Not a character
}

# Characters that are legitimate in normal text
WHITELIST = {
    "\u00ad",  # Soft hyphen — commonly used in word wrapping
    "\ufeff",  # BOM — byte order mark at start of UTF-8 files
    "\u200d",  # ZWJ — zero-width joiner for emoji sequences and Indic scripts
    "\u200c",  # ZWNJ — zero-width non-joiner for Persian/Arabic/Indic scripts
    "\u200e",  # LRM — left-to-right mark for bidi text (common in Hebrew/Arabic)
    "\u200f",  # RLM — right-to-left mark for bidi text
}

# Unicode tag characters (U+E0000-U+E007F) used for ASCII smuggling
TAG_RANGE = range(0xE0000, 0xE0080)


class InvisibleTextScanner(InputScanner):
    """
    Detects invisible Unicode characters in prompts.

    Invisible characters can be used to:
    1. Hide prompt injection instructions from human review
    2. Smuggle ASCII data via Unicode tag characters
    3. Manipulate text direction for display attacks
    4. Bypass input filters that check visible text only

    Extended with Unicode tag character smuggling detection.
    """

    def __init__(
        self,
        threshold: int = 3,
        strip_invisible: bool = True,
        detect_tag_chars: bool = True,
    ):
        """
        Args:
            threshold: Number of invisible chars before flagging (default: 1).
            strip_invisible: If True, remove invisible chars from sanitized output.
            detect_tag_chars: If True, also detect Unicode tag characters (U+E0000-E007F).
        """
        self._threshold = threshold
        self._strip_invisible = strip_invisible
        self._detect_tag_chars = detect_tag_chars

    def scan(self, prompt: str) -> ScanResult:
        """Scan a prompt for invisible Unicode characters."""
        invisible_chars = []
        tag_chars = []

        for i, ch in enumerate(prompt):
            cp = ord(ch)

            # Check Unicode tag characters (ASCII smuggling)
            if self._detect_tag_chars and cp in TAG_RANGE:
                tag_chars.append((i, ch, f"U+{cp:04X}"))
                continue

            # Skip whitelisted characters
            if ch in WHITELIST:
                continue

            # Check always-flag set
            if ch in ALWAYS_FLAG:
                invisible_chars.append((i, ch, f"U+{cp:04X}"))
                continue

            # Check Unicode category
            category = unicodedata.category(ch)
            if category in INVISIBLE_CATEGORIES:
                invisible_chars.append((i, ch, f"U+{cp:04X}"))

        total_suspicious = len(invisible_chars) + len(tag_chars)

        if total_suspicious < self._threshold:
            return ScanResult(
                sanitized=prompt,
                action=ScanAction.PASS,
                risk_score=0.0,
            )

        findings = []

        if invisible_chars:
            # Group by type for cleaner reporting
            char_summary = ", ".join(
                f"{code} at pos {pos}" for pos, ch, code in invisible_chars[:10]
            )
            if len(invisible_chars) > 10:
                char_summary += f" ... and {len(invisible_chars) - 10} more"

            findings.append(Finding.firewall_input(
                rule_id="FIREWALL-INPUT-002",
                title=f"Invisible Unicode characters detected ({len(invisible_chars)})",
                description=(
                    f"Found {len(invisible_chars)} invisible Unicode character(s) in the prompt. "
                    f"These can be used to hide malicious instructions from human review "
                    f"while still being processed by the LLM."
                ),
                severity=Severity.HIGH if len(invisible_chars) > 5 else Severity.MEDIUM,
                target="<prompt>",
                evidence=char_summary,
                cwe_ids=["CWE-116"],  # Improper Encoding or Escaping of Output
                remediation="Strip invisible Unicode characters before processing.",
            ))

        if tag_chars:
            tag_summary = ", ".join(
                f"{code} at pos {pos}" for pos, ch, code in tag_chars[:10]
            )

            findings.append(Finding.firewall_input(
                rule_id="FIREWALL-INPUT-010",
                title=f"Unicode tag character smuggling detected ({len(tag_chars)} chars)",
                description=(
                    f"Found {len(tag_chars)} Unicode tag character(s) (U+E0000-E007F range). "
                    f"This technique embeds invisible ASCII data in text, enabling "
                    f"hidden prompt injection that bypasses visual review."
                ),
                severity=Severity.CRITICAL,
                target="<prompt>",
                evidence=tag_summary,
                tags=["owasp:llm01", "avid-effect:security:S0403"],
                remediation="Strip all Unicode tag characters (U+E0000-E007F) from input.",
            ))

        # Sanitize
        sanitized = prompt
        if self._strip_invisible:
            sanitized = self._remove_invisible(prompt)

        risk_score = min(1.0, total_suspicious / 10.0)

        return ScanResult(
            sanitized=sanitized,
            action=ScanAction.BLOCK if tag_chars else ScanAction.WARN,
            risk_score=risk_score,
            findings=findings,
        )

    def _remove_invisible(self, text: str) -> str:
        """Remove all invisible characters from text."""
        result = []
        for ch in text:
            cp = ord(ch)
            if cp in TAG_RANGE:
                continue
            if ch in WHITELIST:
                result.append(ch)
                continue
            if ch in ALWAYS_FLAG:
                continue
            category = unicodedata.category(ch)
            if category not in INVISIBLE_CATEGORIES:
                result.append(ch)
        return "".join(result)
