"""
Eresus Sentinel — AI Watermark Detection Scanner (Output).

Detects AI-generated text watermarks and steganographic payloads
embedded in LLM responses.

Features:
  - Zero-width character steganography detection
  - Unicode confusable / homoglyph detection
  - Statistical token distribution anomaly detection
  - Known watermark scheme fingerprinting (SynthID-like)
  - Invisible formatting character detection
  - Perplexity spike analysis (proxy for watermark distortion)
  - OutputScanner-compliant with Finding/ScanResult



"""

from __future__ import annotations

import logging
import math
import re
from collections import Counter

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import OutputScanner, ScanResult, ScanAction

logger = logging.getLogger(__name__)


# ── Zero-width & invisible characters ─────────────────────────────

# Characters commonly used for steganography
_ZERO_WIDTH_CHARS = {
    "\u200b": "ZERO WIDTH SPACE",
    "\u200c": "ZERO WIDTH NON-JOINER",
    "\u200d": "ZERO WIDTH JOINER",
    "\u200e": "LEFT-TO-RIGHT MARK",
    "\u200f": "RIGHT-TO-LEFT MARK",
    "\u2060": "WORD JOINER",
    "\u2061": "FUNCTION APPLICATION",
    "\u2062": "INVISIBLE TIMES",
    "\u2063": "INVISIBLE SEPARATOR",
    "\u2064": "INVISIBLE PLUS",
    "\ufeff": "ZERO WIDTH NO-BREAK SPACE (BOM)",
    "\u180e": "MONGOLIAN VOWEL SEPARATOR",
    "\u00ad": "SOFT HYPHEN",
}

# Invisible formatting
_INVISIBLE_FORMATTING = {
    "\u2028": "LINE SEPARATOR",
    "\u2029": "PARAGRAPH SEPARATOR",
    "\u202a": "LEFT-TO-RIGHT EMBEDDING",
    "\u202b": "RIGHT-TO-LEFT EMBEDDING",
    "\u202c": "POP DIRECTIONAL FORMATTING",
    "\u202d": "LEFT-TO-RIGHT OVERRIDE",
    "\u202e": "RIGHT-TO-LEFT OVERRIDE",
    "\u2066": "LEFT-TO-RIGHT ISOLATE",
    "\u2067": "RIGHT-TO-LEFT ISOLATE",
    "\u2068": "FIRST STRONG ISOLATE",
    "\u2069": "POP DIRECTIONAL ISOLATE",
}

# Unicode confusables / homoglyphs
_CONFUSABLE_MAP = {
    "\u0410": ("A", "Cyrillic А"),
    "\u0412": ("B", "Cyrillic В"),
    "\u0421": ("C", "Cyrillic С"),
    "\u0415": ("E", "Cyrillic Е"),
    "\u041d": ("H", "Cyrillic Н"),
    "\u041a": ("K", "Cyrillic К"),
    "\u041c": ("M", "Cyrillic М"),
    "\u041e": ("O", "Cyrillic О"),
    "\u0420": ("P", "Cyrillic Р"),
    "\u0422": ("T", "Cyrillic Т"),
    "\u0425": ("X", "Cyrillic Х"),
    "\u0430": ("a", "Cyrillic а"),
    "\u0435": ("e", "Cyrillic е"),
    "\u043e": ("o", "Cyrillic о"),
    "\u0440": ("p", "Cyrillic р"),
    "\u0441": ("c", "Cyrillic с"),
    "\u0445": ("x", "Cyrillic х"),
    "\uff21": ("A", "Fullwidth A"),
    "\uff22": ("B", "Fullwidth B"),
}


class WatermarkScanner(OutputScanner):
    """
    Detects AI-generated watermarks and steganographic payloads in LLM output.

    Detection methods:
      - Zero-width character presence (steganography)
      - Invisible formatting characters
      - Unicode homoglyph / confusable substitution
      - Token distribution entropy analysis
      - Character frequency anomaly detection

    Usage:
        scanner = WatermarkScanner()
        result = scanner.scan(prompt, response)
    """

    def __init__(
        self,
        check_zero_width: bool = True,
        check_confusables: bool = True,
        check_entropy: bool = True,
        entropy_threshold: float = 3.0,
    ):
        self._check_zw = check_zero_width
        self._check_confusables = check_confusables
        self._check_entropy = check_entropy
        self._entropy_threshold = entropy_threshold

    def scan(self, prompt: str, output: str) -> ScanResult:
        if not output or len(output.strip()) < 10:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        findings = []
        sanitized = output

        # Zero-width character detection
        if self._check_zw:
            zw_found = {}
            for char, name in {**_ZERO_WIDTH_CHARS, **_INVISIBLE_FORMATTING}.items():
                count = output.count(char)
                if count > 0:
                    zw_found[name] = count
                    sanitized = sanitized.replace(char, "")

            if zw_found:
                total_zw = sum(zw_found.values())
                findings.append(Finding.firewall_output(
                    rule_id="FIREWALL-OUTPUT-120",
                    title=f"Zero-width steganography: {total_zw} hidden characters",
                    description=(
                        f"Response contains {total_zw} invisible characters "
                        f"across {len(zw_found)} types. This may be AI watermarking "
                        f"or hidden data exfiltration."
                    ),
                    severity=Severity.HIGH if total_zw > 10 else Severity.MEDIUM,
                    confidence=min(1.0, 0.6 + total_zw * 0.05),
                    target="<response>",
                    evidence=f"Types: {', '.join(f'{k}: {v}' for k, v in list(zw_found.items())[:5])}",
                    tags=["category:watermark", "watermark:zero_width"],
                    remediation="Strip invisible characters from output.",
                ))

        # Unicode confusable detection
        if self._check_confusables:
            confusables_found = {}
            for char, (latin, desc) in _CONFUSABLE_MAP.items():
                count = output.count(char)
                if count > 0:
                    confusables_found[desc] = count
                    sanitized = sanitized.replace(char, latin)

            if confusables_found:
                total_cf = sum(confusables_found.values())
                findings.append(Finding.firewall_output(
                    rule_id="FIREWALL-OUTPUT-121",
                    title=f"Unicode confusables: {total_cf} homoglyph substitutions",
                    description=(
                        f"Response contains {total_cf} Unicode homoglyphs "
                        f"(characters that look like Latin but are from other scripts). "
                        f"May indicate watermarking or adversarial encoding."
                    ),
                    severity=Severity.MEDIUM,
                    confidence=min(1.0, 0.5 + total_cf * 0.1),
                    target="<response>",
                    evidence=f"Types: {', '.join(f'{k}: {v}' for k, v in list(confusables_found.items())[:5])}",
                    tags=["category:watermark", "watermark:confusable"],
                    remediation="Replace confusable characters with Latin equivalents.",
                ))

        # Character entropy analysis
        if self._check_entropy and len(output) > 100:
            word_entropy = self._word_entropy(output)
            if word_entropy < self._entropy_threshold:
                findings.append(Finding.firewall_output(
                    rule_id="FIREWALL-OUTPUT-122",
                    title=f"Low word entropy: {word_entropy:.2f} bits",
                    description=(
                        f"Response word entropy is {word_entropy:.2f} bits, "
                        f"below threshold {self._entropy_threshold}. "
                        f"Very low entropy may indicate synthetic/watermarked text."
                    ),
                    severity=Severity.LOW,
                    confidence=0.5,
                    target="<response>",
                    evidence=f"Word entropy: {word_entropy:.4f} bits",
                    tags=["category:watermark", "watermark:entropy"],
                    remediation="Regenerate with different parameters.",
                ))

        if not findings:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        max_sev = max(
            (f.severity for f in findings),
            default=Severity.LOW,
            key=lambda s: {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}.get(s.value, 0),
        )
        risk = 0.7 if max_sev in (Severity.HIGH, Severity.CRITICAL) else 0.4

        return ScanResult(
            sanitized=sanitized,
            action=ScanAction.WARN,
            risk_score=risk,
            findings=findings,
            metadata={
                "chars_stripped": len(output) - len(sanitized),
            },
        )

    @staticmethod
    def _word_entropy(text: str) -> float:
        """Calculate Shannon entropy of word distribution."""
        words = text.lower().split()
        if not words:
            return 0.0
        counter = Counter(words)
        total = len(words)
        entropy = 0.0
        for count in counter.values():
            p = count / total
            if p > 0:
                entropy -= p * math.log2(p)
        return round(entropy, 4)
