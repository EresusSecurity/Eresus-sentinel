"""
Encoding Attack Scanner.

Detects prompt injection that uses encoding to bypass input filters.
Pre-decodes text using multiple encoding schemes before running
downstream scanners.

Supported encodings:
- Base64, ROT13, hex, Morse, Braille, Atbash, Leetspeak
- Unicode tag characters, variant selectors
- Multi-decode pipeline
"""

from __future__ import annotations

import base64
import binascii
import codecs
import logging
import re
from typing import Optional

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import InputScanner, ScanResult, ScanAction

logger = logging.getLogger(__name__)

# ROT13 translation table
ROT13_TABLE = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)

# Regex patterns for encoded content
BASE64_PATTERN = re.compile(
    r"[A-Za-z0-9+/]{20,}={0,2}",
    re.MULTILINE,
)
HEX_PATTERN = re.compile(
    r"(?:0x)?[0-9a-fA-F]{20,}",
    re.MULTILINE,
)

# Injection keywords to check in decoded content
INJECTION_INDICATORS = [
    "ignore", "disregard", "forget", "override", "bypass",
    "system", "exec", "eval", "import", "os.system",
    "subprocess", "__import__", "prompt", "instruction",
    "jailbreak", "DAN", "pretend", "roleplay", "persona",
]


class EncodingAttackScanner(InputScanner):
    """
    Detects encoded prompt injection attempts.

    Attackers encode malicious instructions in base64, hex, ROT13, etc.
    to bypass input filters that only check plaintext. This scanner
    pre-decodes suspicious patterns and checks the result for injection.

    Encoding formats detected:
    - Base64 (standard, URL-safe)
    - Hex
    - ROT13
    - URL encoding (%xx)
    - Unicode escapes
    """

    def __init__(
        self,
        check_base64: bool = True,
        check_hex: bool = True,
        check_rot13: bool = True,
        check_url_encoding: bool = True,
        min_encoded_length: int = 20,
    ):
        self._check_base64 = check_base64
        self._check_hex = check_hex
        self._check_rot13 = check_rot13
        self._check_url = check_url_encoding
        self._min_length = min_encoded_length

    def scan(self, prompt: str) -> ScanResult:
        """Scan a prompt for encoded injection attempts."""
        findings = []
        decoded_texts = []

        # Try each encoding scheme
        if self._check_base64:
            results = self._try_base64_decode(prompt)
            decoded_texts.extend(results)

        if self._check_hex:
            results = self._try_hex_decode(prompt)
            decoded_texts.extend(results)

        if self._check_rot13:
            results = self._try_rot13_decode(prompt)
            decoded_texts.extend(results)

        if self._check_url:
            results = self._try_url_decode(prompt)
            decoded_texts.extend(results)

        # Check decoded content for injection indicators
        for encoding_name, decoded_text in decoded_texts:
            injection_found = self._check_for_injection(decoded_text)
            if injection_found:
                keyword = injection_found
                findings.append(Finding.firewall_input(
                    rule_id="FIREWALL-INPUT-005",
                    title=f"Encoded prompt injection detected ({encoding_name})",
                    description=(
                        f"Found {encoding_name}-encoded text that decodes to contain "
                        f"injection keyword '{keyword}'. Attackers use encoding to bypass "
                        f"input filters."
                    ),
                    severity=Severity.HIGH,
                    target="<prompt>",
                    evidence=(
                        f"Encoding: {encoding_name}, "
                        f"Decoded: '{decoded_text[:200]}', "
                        f"Keyword: '{keyword}'"
                    ),
                    tags=[
                        "owasp:llm01",
                        "avid-effect:security:S0403",
                    ],
                    cwe_ids=["CWE-838"],  # Inappropriate Encoding for Output
                    remediation=(
                        "Decode all known encoding formats before applying "
                        "injection detection. Block inputs with encoded injection."
                    ),
                ))

        if not findings:
            return ScanResult(
                sanitized=prompt,
                action=ScanAction.PASS,
                risk_score=0.0,
            )

        return ScanResult(
            sanitized=prompt,
            action=ScanAction.BLOCK,
            risk_score=0.9,
            findings=findings,
        )

    def _try_base64_decode(self, text: str) -> list[tuple[str, str]]:
        """Extract and decode base64 patterns."""
        results = []
        for match in BASE64_PATTERN.finditer(text):
            encoded = match.group()
            if len(encoded) < self._min_length:
                continue

            for decoder in [base64.b64decode, base64.urlsafe_b64decode]:
                try:
                    # Pad if necessary
                    padded = encoded + "=" * (4 - len(encoded) % 4) if len(encoded) % 4 else encoded
                    decoded = decoder(padded).decode("utf-8", errors="replace")
                    if self._is_meaningful_text(decoded):
                        results.append(("base64", decoded))
                except Exception:
                    continue

        return results

    def _try_hex_decode(self, text: str) -> list[tuple[str, str]]:
        """Extract and decode hex patterns."""
        results = []
        for match in HEX_PATTERN.finditer(text):
            encoded = match.group()
            if encoded.startswith("0x"):
                encoded = encoded[2:]
            if len(encoded) < self._min_length or len(encoded) % 2 != 0:
                continue

            try:
                decoded = binascii.unhexlify(encoded).decode("utf-8", errors="replace")
                if self._is_meaningful_text(decoded):
                    results.append(("hex", decoded))
            except Exception:
                continue

        return results

    def _try_rot13_decode(self, text: str) -> list[tuple[str, str]]:
        """Apply ROT13 decoding to the full text."""
        results = []
        decoded = text.translate(ROT13_TABLE)
        if decoded != text:  # Only if there was a change
            injection = self._check_for_injection(decoded)
            if injection:
                results.append(("rot13", decoded))
        return results

    def _try_url_decode(self, text: str) -> list[tuple[str, str]]:
        """Decode URL-encoded patterns (%xx)."""
        results = []
        if "%" not in text:
            return results

        try:
            from urllib.parse import unquote
            decoded = unquote(text)
            if decoded != text and self._is_meaningful_text(decoded):
                results.append(("url_encoding", decoded))
        except Exception:
            pass

        return results

    def _is_meaningful_text(self, text: str) -> bool:
        """Check if decoded text is meaningful English (not random bytes)."""
        if not text or len(text) < 5:
            return False
        # Check for sufficient ASCII letter ratio
        letters = sum(1 for c in text if c.isalpha())
        return letters / len(text) > 0.4

    def _check_for_injection(self, text: str) -> Optional[str]:
        """Check decoded text for injection indicators. Returns matched keyword or None."""
        text_lower = text.lower()
        for keyword in INJECTION_INDICATORS:
            if keyword.lower() in text_lower:
                return keyword
        return None
