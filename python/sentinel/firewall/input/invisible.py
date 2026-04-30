"""
Invisible Text Scanner.

Detects invisible/zero-width Unicode characters in prompts that can
be used to obfuscate prompt injection attacks.

Uses unicodedata.category() to detect Cf (Format), Co (Private Use),
and Cn (Unassigned) Unicode categories.
"""

from __future__ import annotations

import logging
import unicodedata

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import InputScanner, ScanAction, ScanResult

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

# Homoglyph confusable map: Cyrillic/Greek chars that look identical to Latin ASCII
# Key = confusable char, Value = Latin equivalent it mimics
HOMOGLYPH_MAP = {
    "\u0410": "A", "\u0412": "B", "\u0421": "C", "\u0415": "E",
    "\u041d": "H", "\u0406": "I", "\u041a": "K", "\u041c": "M",
    "\u041e": "O", "\u0420": "P", "\u0422": "T", "\u0425": "X",
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x", "\u0456": "i",
    "\u0455": "s", "\u0458": "j", "\u04bb": "h",
    # Greek
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0397": "H",
    "\u0399": "I", "\u039a": "K", "\u039c": "M", "\u039d": "N",
    "\u039f": "O", "\u03a1": "P", "\u03a4": "T", "\u03a7": "X",
    "\u03bf": "o", "\u03b1": "a",
}

# Dangerous bidi/directional override characters — always flag even with threshold=1
# These can disguise filenames (e.g., "invoice_RLO_cod.exe" appears as "invoice_exe.doc")
BIDI_OVERRIDE_CHARS = {
    "\u202a",  # LEFT-TO-RIGHT EMBEDDING
    "\u202b",  # RIGHT-TO-LEFT EMBEDDING
    "\u202c",  # POP DIRECTIONAL FORMATTING
    "\u202d",  # LEFT-TO-RIGHT OVERRIDE
    "\u202e",  # RIGHT-TO-LEFT OVERRIDE
    "\u2066",  # LEFT-TO-RIGHT ISOLATE
    "\u2067",  # RIGHT-TO-LEFT ISOLATE
    "\u2068",  # FIRST STRONG ISOLATE
    "\u2069",  # POP DIRECTIONAL ISOLATE
}


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
        detect_homoglyphs: bool = True,
    ):
        """
        Args:
            threshold: Number of invisible chars before flagging (default: 1).
            strip_invisible: If True, remove invisible chars from sanitized output.
            detect_tag_chars: If True, also detect Unicode tag characters (U+E0000-E007F).
            detect_homoglyphs: If True, detect Cyrillic/Greek lookalike characters.
        """
        self._threshold = threshold
        self._strip_invisible = strip_invisible
        self._detect_tag_chars = detect_tag_chars
        self._detect_homoglyphs = detect_homoglyphs

    def scan(self, prompt: str) -> ScanResult:
        """Scan a prompt for invisible Unicode characters."""
        invisible_chars = []
        tag_chars = []
        bidi_chars = []
        homoglyph_chars = []

        for i, ch in enumerate(prompt):
            cp = ord(ch)

            # Check Unicode tag characters (ASCII smuggling)
            if self._detect_tag_chars and cp in TAG_RANGE:
                tag_chars.append((i, ch, f"U+{cp:04X}"))
                continue

            # Check bidi override characters (always dangerous, threshold=1)
            if ch in BIDI_OVERRIDE_CHARS:
                bidi_chars.append((i, ch, f"U+{cp:04X}"))
                continue

            # Check homoglyph confusables (Cyrillic/Greek lookalikes)
            if self._detect_homoglyphs and ch in HOMOGLYPH_MAP:
                homoglyph_chars.append((i, ch, HOMOGLYPH_MAP[ch]))
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

        total_suspicious = len(invisible_chars) + len(tag_chars) + len(bidi_chars) + len(homoglyph_chars)

        # Bidi overrides and homoglyphs bypass the normal threshold — always flag if any found
        if total_suspicious < self._threshold and not bidi_chars and not homoglyph_chars:
            return ScanResult(
                sanitized=prompt,
                action=ScanAction.PASS,
                risk_score=0.0,
            )

        findings = []

        if bidi_chars:
            bidi_summary = ", ".join(
                f"{code} at pos {pos}" for pos, ch, code in bidi_chars[:10]
            )
            findings.append(Finding.firewall_input(
                rule_id="FIREWALL-INPUT-012",
                title=f"RTL/Bidi override characters detected ({len(bidi_chars)})",
                description=(
                    f"Found {len(bidi_chars)} bidirectional override character(s). "
                    f"These can reverse text rendering to disguise malicious content "
                    f"(e.g., making 'exe.doc' appear as 'doc.exe')."
                ),
                severity=Severity.HIGH,
                target="<prompt>",
                evidence=bidi_summary,
                cwe_ids=["CWE-116"],
                tags=["owasp:llm01", "avid-effect:security:S0403"],
                remediation="Strip all bidirectional override characters (U+202A-202E, U+2066-2069) from input.",
            ))

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

        if homoglyph_chars:
            homo_summary = ", ".join(
                f"'{ch}' (U+{ord(ch):04X}) looks like '{latin}' at pos {pos}"
                for pos, ch, latin in homoglyph_chars[:10]
            )
            if len(homoglyph_chars) > 10:
                homo_summary += f" ... and {len(homoglyph_chars) - 10} more"
            findings.append(Finding.firewall_input(
                rule_id="FIREWALL-INPUT-013",
                title=f"Homoglyph/confusable characters detected ({len(homoglyph_chars)})",
                description=(
                    f"Found {len(homoglyph_chars)} character(s) from Cyrillic/Greek scripts "
                    f"that visually mimic Latin letters. These can bypass keyword filters "
                    f"(e.g., Cyrillic 'А' looks identical to Latin 'A')."
                ),
                severity=Severity.HIGH,
                target="<prompt>",
                evidence=homo_summary,
                cwe_ids=["CWE-176"],
                tags=["owasp:llm01", "avid-effect:security:S0403"],
                remediation="Normalize text to ASCII/NFC before processing, or reject mixed-script input.",
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
            if ch in BIDI_OVERRIDE_CHARS:
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
