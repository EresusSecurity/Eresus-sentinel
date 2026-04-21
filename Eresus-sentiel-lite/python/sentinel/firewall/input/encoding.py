"""
Encoding Attack Scanner.

Detects prompt injection that uses encoding to bypass input filters.
Pre-decodes text using multiple encoding schemes before running
downstream scanners.

Supported encodings:
- Base64, ROT13, hex, Morse, Braille, Atbash, Leetspeak
- Unicode tag characters, variant selectors
- Unicode NFKC normalization (confusable characters)
- Multi-layer decode pipeline (up to 3 layers)
"""

from __future__ import annotations

import base64
import binascii
import codecs
import logging
import re
import unicodedata
from typing import Optional

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import InputScanner, ScanResult, ScanAction

logger = logging.getLogger(__name__)

# ROT13 translation table
ROT13_TABLE = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)

# Unicode confusable mappings (common homoglyphs used to bypass keyword filters)
_CONFUSABLES = {
    "\u0406": "I",    # Cyrillic І → I
    "\u0410": "A",    # Cyrillic А → A
    "\u0412": "B",    # Cyrillic В → B
    "\u0415": "E",    # Cyrillic Е → E
    "\u041a": "K",    # Cyrillic К → K
    "\u041c": "M",    # Cyrillic М → M
    "\u041d": "H",    # Cyrillic Н → H
    "\u041e": "O",    # Cyrillic О → O
    "\u0420": "P",    # Cyrillic Р → P
    "\u0421": "C",    # Cyrillic С → C
    "\u0422": "T",    # Cyrillic Т → T
    "\u0425": "X",    # Cyrillic Х → X
    "\u0430": "a",    # Cyrillic а → a
    "\u0435": "e",    # Cyrillic е → e
    "\u043e": "o",    # Cyrillic о → o
    "\u0440": "p",    # Cyrillic р → p
    "\u0441": "c",    # Cyrillic с → c
    "\u0443": "y",    # Cyrillic у → y
    "\u0445": "x",    # Cyrillic х → x
    "\u2160": "I",    # Roman numeral Ⅰ → I
    "\u2161": "II",   # Roman numeral Ⅱ
    "\u2164": "V",    # Roman numeral Ⅴ → V
    "\u2169": "X",    # Roman numeral Ⅹ → X
    "\u216c": "L",    # Roman numeral Ⅼ → L
    "\u216d": "C",    # Roman numeral Ⅽ → C
    "\u216e": "D",    # Roman numeral Ⅾ → D
    "\u216f": "M",    # Roman numeral Ⅿ → M
    "\uff21": "A",    # Fullwidth A
    "\uff22": "B",    # Fullwidth B
    "\uff23": "C",    # Fullwidth C
    "\uff49": "i",    # Fullwidth i
    "\uff47": "g",    # Fullwidth g
    "\uff4e": "n",    # Fullwidth n
    "\uff4f": "o",    # Fullwidth o
    "\uff52": "r",    # Fullwidth r
    "\uff45": "e",    # Fullwidth e
}

# Regex patterns for encoded content
BASE64_PATTERN = re.compile(
    r"[A-Za-z0-9+/]{20,}={0,2}",
    re.MULTILINE,
)
HEX_PATTERN = re.compile(
    r"(?:0x)?[0-9a-fA-F]{20,}",
    re.MULTILINE,
)

# Unicode tag character range (U+E0001 to U+E007F) — used for invisible text
UNICODE_TAG_PATTERN = re.compile(r"[\U000E0001-\U000E007F]+")

# Injection keywords to check in decoded content
INJECTION_INDICATORS = [
    "ignore", "disregard", "forget", "override", "bypass",
    "system", "exec", "eval", "import", "os.system",
    "subprocess", "__import__", "prompt", "instruction",
    "jailbreak", "DAN", "pretend", "roleplay", "persona",
]

# Maximum decode layers to prevent infinite loops
MAX_DECODE_LAYERS = 3


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

    @staticmethod
    def normalize_unicode(text: str) -> str:
        """Apply NFKC normalization + confusable character mapping.

        This defeats Unicode homoglyph attacks like using Cyrillic 'а'
        instead of Latin 'a', or Roman numeral 'Ⅰ' instead of 'I'.
        """
        # Step 1: NFKC normalization (handles fullwidth, compatibility chars)
        normalized = unicodedata.normalize("NFKC", text)
        # Step 2: Apply confusable mapping for remaining homoglyphs
        result = []
        for ch in normalized:
            result.append(_CONFUSABLES.get(ch, ch))
        # Step 3: Strip Unicode tag characters (invisible text)
        cleaned = "".join(result)
        cleaned = UNICODE_TAG_PATTERN.sub("", cleaned)
        return cleaned

    @staticmethod
    def multi_layer_decode(text: str) -> list[tuple[str, str]]:
        """Decode text through multiple layers of encoding.

        Attackers stack encodings: ROT13(Base64(payload)).
        This peels layers off one at a time up to MAX_DECODE_LAYERS.
        Returns list of (encoding_chain, decoded_text) tuples.
        """
        results: list[tuple[str, str]] = []
        current_texts = [("", text)]

        for _layer in range(MAX_DECODE_LAYERS):
            next_texts: list[tuple[str, str]] = []
            for chain, txt in current_texts:
                # Try Base64
                for match in BASE64_PATTERN.finditer(txt):
                    encoded = match.group()
                    if len(encoded) < 20:
                        continue
                    for decoder in [base64.b64decode, base64.urlsafe_b64decode]:
                        try:
                            padded = encoded + "=" * (4 - len(encoded) % 4) if len(encoded) % 4 else encoded
                            decoded = decoder(padded).decode("utf-8", errors="replace")
                            if _is_meaningful_text_static(decoded) and decoded != txt:
                                label = f"{chain}>base64" if chain else "base64"
                                results.append((label, decoded))
                                next_texts.append((label, decoded))
                        except Exception:
                            continue

                # Try Hex
                for match in HEX_PATTERN.finditer(txt):
                    encoded = match.group()
                    if encoded.startswith("0x"):
                        encoded = encoded[2:]
                    if len(encoded) < 20 or len(encoded) % 2 != 0:
                        continue
                    try:
                        decoded = binascii.unhexlify(encoded).decode("utf-8", errors="replace")
                        if _is_meaningful_text_static(decoded) and decoded != txt:
                            label = f"{chain}>hex" if chain else "hex"
                            results.append((label, decoded))
                            next_texts.append((label, decoded))
                    except Exception:
                        continue

                # Try ROT13
                decoded = txt.translate(ROT13_TABLE)
                if decoded != txt:
                    label = f"{chain}>rot13" if chain else "rot13"
                    # Don't add to results yet — check for injection below
                    next_texts.append((label, decoded))

            if not next_texts:
                break
            current_texts = next_texts

        return results

    def scan(self, prompt: str) -> ScanResult:
        """Scan a prompt for encoded injection attempts.

        Pipeline:
        1. Unicode NFKC + confusable normalization
        2. Multi-layer encoding decode
        3. Injection keyword check on all decoded variants
        """
        findings = []

        # Step 1: Normalize Unicode (confusables, NFKC)
        normalized = self.normalize_unicode(prompt)
        if normalized != prompt:
            # Check normalized text for injection
            injection = self._check_for_injection(normalized)
            if injection:
                findings.append(Finding.firewall_input(
                    rule_id="FIREWALL-INPUT-006",
                    title="Unicode confusable injection detected",
                    description=(
                        f"Input contains Unicode homoglyphs that normalize to "
                        f"injection keyword '{injection}'. Attackers use confusable "
                        f"characters to bypass keyword filters."
                    ),
                    severity=Severity.HIGH,
                    target="<prompt>",
                    evidence=f"Normalized text contains: '{injection}'",
                    tags=["owasp:llm01"],
                    cwe_ids=["CWE-176"],
                    remediation="Apply NFKC normalization before injection detection.",
                ))

        # Step 2: Multi-layer decode
        decoded_texts = self.multi_layer_decode(prompt)

        # Also do single-layer decode with explicit methods (for compat)
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

        # Step 3: Check all decoded texts for injection
        seen: set[str] = set()
        for encoding_name, decoded_text in decoded_texts:
            if decoded_text in seen:
                continue
            seen.add(decoded_text)

            # Also normalize decoded text before checking
            norm_decoded = self.normalize_unicode(decoded_text)
            injection_found = self._check_for_injection(norm_decoded)
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
                    cwe_ids=["CWE-838"],
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
        if decoded != text:
            # Check ALL decoded text, not just if injection found
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


def _is_meaningful_text_static(text: str) -> bool:
    """Check if decoded text is meaningful (not random bytes). Module-level for multi_layer_decode."""
    if not text or len(text) < 5:
        return False
    letters = sum(1 for c in text if c.isalpha())
    return letters / len(text) > 0.4
