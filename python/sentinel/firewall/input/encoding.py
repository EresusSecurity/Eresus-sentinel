"""
Encoding Attack Scanner  (v2 — modular architecture).

Detects prompt injection that uses encoding to bypass input filters.
Pre-decodes text using multiple encoding schemes before running
downstream keyword / reverse-shell checks.

Supported encodings:
- Base64 (standard, URL-safe), Base32, Base85/Ascii85
- Hex (0x-prefix, C-style \\x41, space-delimited)
- ROT13, ROT47, ROT18, ROT5, Atbash
- Caesar brute-force (all 25 shifts)
- URL encoding (including double/triple)
- HTML entities (&#105; &#x69; &amp;)
- Quoted-Printable (=69=67=6e)
- Unicode NFKC + confusable normalization
- Full-width / math / superscript Unicode normalization
- Unicode tag steganography (U+E0020-U+E007E)
- Zero-width character bombs
- Emoji variation selector steganography
- Zalgo / stacking combining marks
- Brainfuck program detection
- Morse code decode
- Leet-speak normalization (1gn0r3 -> ignore)
- Multi-layer decode pipeline (up to 3 layers)

Architecture:
  _enc_tables.py    -- cipher tables, maps, compiled regexes
  _enc_decoders.py  -- pure decode functions (stateless)
  _enc_detectors.py -- detection predicates (bool / match)
  encoding.py       -- EncodingAttackScanner (this file, ~270 lines)
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import InputScanner, ScanAction, ScanResult

from sentinel.firewall.input._enc_tables import (
    FULLWIDTH_PATTERN,
    INJECTION_INDICATORS,
)
from sentinel.firewall.input._enc_decoders import (
    apply_atbash,
    apply_rot18,
    apply_rot47,
    caesar_brute,
    decode_morse,
    decode_unicode_tags,
    is_likely_leet,
    is_meaningful,
    multi_layer_decode,
    normalize_fullwidth,
    normalize_leet,
    normalize_math_unicode,
    normalize_superscript_subscript,
    normalize_unicode,
    strip_zero_width,
    try_base32,
    try_base64,
    try_base85,
    try_hex,
    try_hex_escape,
    try_html_entity_decode,
    try_quoted_printable,
    try_rot13,
    try_rot47,
    try_url_decode,
)
from sentinel.firewall.input._enc_detectors import (
    check_injection,
    detect_brainfuck,
    detect_mixed_scripts,
    detect_morse,
    detect_reverse_shell,
    detect_variation_selectors,
    detect_web_shell,
    detect_zalgo,
    detect_zero_width,
)

logger = logging.getLogger(__name__)

__all__ = [
    "EncodingAttackScanner",
    "normalize_leet", "normalize_unicode", "normalize_fullwidth",
    "normalize_math_unicode", "normalize_superscript_subscript",
    "apply_rot47", "apply_rot18", "apply_atbash",
    "decode_morse", "decode_unicode_tags", "strip_zero_width",
    "detect_zalgo", "detect_brainfuck", "detect_variation_selectors",
    "is_meaningful", "multi_layer_decode",
    "INJECTION_INDICATORS",
]


class EncodingAttackScanner(InputScanner):
    """Detect encoded prompt injection and reverse-shell payloads.

    Pipeline:
    1. Mixed-script (homoglyph) detection.
    2. Unicode NFKC + confusable normalization.
    3. Multi-layer decode (base64 -> hex -> ROT13 stacks, up to 3 deep).
    4. All single-layer decoders in sequence.
    5. Every decoded variant checked for injection keywords,
       reverse-shell patterns, and web-shell patterns.
    """

    def __init__(
        self,
        check_base64: bool = True,
        check_hex: bool = True,
        check_rot13: bool = True,
        check_url_encoding: bool = True,
        min_encoded_length: int = 20,
        check_rot47: bool = True,
        check_rot18: bool = True,
        check_atbash: bool = True,
        check_fullwidth: bool = True,
        check_math_unicode: bool = True,
        check_superscript: bool = True,
        check_morse: bool = True,
        check_brainfuck: bool = True,
        check_zalgo: bool = True,
        check_zero_width: bool = True,
        check_variation_selectors: bool = True,
        check_unicode_tags: bool = True,
        check_leet: bool = True,
        check_hex_escape: bool = True,
        check_base32: bool = True,
        check_base85: bool = True,
        check_html_entity: bool = True,
        check_quoted_printable: bool = True,
        check_caesar_brute: bool = True,
    ):
        self._check_base64 = check_base64
        self._check_hex = check_hex
        self._check_rot13 = check_rot13
        self._check_url = check_url_encoding
        self._min_length = min_encoded_length
        self._check_rot47 = check_rot47
        self._check_rot18 = check_rot18
        self._check_atbash = check_atbash
        self._check_fullwidth = check_fullwidth
        self._check_math_unicode = check_math_unicode
        self._check_superscript = check_superscript
        self._check_morse = check_morse
        self._check_brainfuck = check_brainfuck
        self._check_zalgo = check_zalgo
        self._check_zero_width = check_zero_width
        self._check_variation_selectors = check_variation_selectors
        self._check_unicode_tags = check_unicode_tags
        self._check_leet = check_leet
        self._check_hex_escape = check_hex_escape
        self._check_base32 = check_base32
        self._check_base85 = check_base85
        self._check_html_entity = check_html_entity
        self._check_quoted_printable = check_quoted_printable
        self._check_caesar_brute = check_caesar_brute

    @staticmethod
    def normalize_unicode(text: str) -> str:
        return normalize_unicode(text)

    @staticmethod
    def multi_layer_decode(text: str) -> list[tuple[str, str]]:
        return multi_layer_decode(text)

    def scan(self, prompt: str) -> ScanResult:
        findings: list[Finding] = []

        # 0. Homoglyph detection
        mixed = detect_mixed_scripts(prompt)
        if mixed:
            examples = ", ".join(f"'{w}' ({s})" for w, s, _ in mixed[:5])
            findings.append(Finding.firewall_input(
                rule_id="FIREWALL-INPUT-011",
                title=f"Homoglyph attack: mixed-script text ({len(mixed)} words)",
                description=(
                    f"Input mixes characters from different scripts in {len(mixed)} word(s)."
                ),
                severity=Severity.MEDIUM,
                target="<prompt>",
                evidence=f"Mixed-script words: {examples}",
                tags=["owasp:llm01", "avid-effect:security:S0403"],
                cwe_ids=["CWE-176"],
                remediation="Apply NFKC normalization and confusable mapping.",
            ))

        # 1. Unicode normalization
        normalized = normalize_unicode(prompt)

        # 1a. Check plain (un-encoded) text directly for reverse/web shell patterns
        _plain_rs = detect_reverse_shell(normalized)
        if _plain_rs:
            findings.append(Finding.firewall_input(
                rule_id="FIREWALL-INPUT-030",
                title="Reverse shell payload in prompt",
                description=f"Plain-text reverse shell command detected: '{_plain_rs}'.",
                severity=Severity.CRITICAL,
                target="<prompt>",
                evidence=f"pattern='{_plain_rs}', text='{prompt[:200]}'",
                tags=["owasp:llm01", "owasp:llm02"],
                cwe_ids=["CWE-78"],
                remediation="Block all inputs containing shell command execution patterns.",
            ))
        _plain_ws = detect_web_shell(normalized)
        if _plain_ws:
            findings.append(Finding.firewall_input(
                rule_id="FIREWALL-INPUT-031",
                title="Web shell pattern in prompt",
                description=f"Plain-text web shell command detected: '{_plain_ws}'.",
                severity=Severity.CRITICAL,
                target="<prompt>",
                evidence=f"pattern='{_plain_ws}', text='{prompt[:200]}'",
                tags=["owasp:llm01", "owasp:llm02"],
                cwe_ids=["CWE-94"],
                remediation="Block all inputs containing web shell patterns.",
            ))

        if normalized != prompt:
            kw = check_injection(normalized)
            if kw:
                findings.append(Finding.firewall_input(
                    rule_id="FIREWALL-INPUT-006",
                    title="Unicode confusable injection",
                    description=f"Homoglyphs normalise to injection keyword '{kw}'.",
                    severity=Severity.HIGH,
                    target="<prompt>",
                    evidence=f"Normalized contains: '{kw}'",
                    tags=["owasp:llm01"],
                    cwe_ids=["CWE-176"],
                    remediation="Apply NFKC normalization before injection detection.",
                ))

        # 2. Collect all decoded variants
        decoded_texts: list[tuple[str, str]] = []
        decoded_texts.extend(multi_layer_decode(prompt))

        if self._check_base64:
            decoded_texts.extend(try_base64(prompt, self._min_length))
        if self._check_hex:
            decoded_texts.extend(try_hex(prompt, self._min_length))
        if self._check_rot13:
            decoded_texts.extend(try_rot13(prompt))
        if self._check_url:
            decoded_texts.extend(try_url_decode(prompt))

        zw_found, zw_count = detect_zero_width(prompt)
        if self._check_zero_width and zw_found:
            decoded_texts.append(("zero_width_stripped", strip_zero_width(prompt)))
            if zw_count > 3:
                findings.append(Finding.firewall_input(
                    rule_id="FIREWALL-INPUT-020",
                    title="Zero-width character injection / token bomb",
                    description="Zero-width chars used for steganography or keyword splitting.",
                    severity=Severity.HIGH,
                    target="<prompt>",
                    evidence=f"Found {zw_count} zero-width chars",
                    tags=["owasp:llm01"],
                    cwe_ids=["CWE-176"],
                    remediation="Strip zero-width characters before processing.",
                ))

        if self._check_unicode_tags:
            tag_dec = decode_unicode_tags(prompt)
            if tag_dec:
                decoded_texts.append(("unicode_tags", tag_dec))
                findings.append(Finding.firewall_input(
                    rule_id="FIREWALL-INPUT-021",
                    title="Unicode tag block steganography",
                    description=f"Invisible tags decode to: '{tag_dec[:100]}'",
                    severity=Severity.HIGH,
                    target="<prompt>",
                    evidence=f"Unicode tag payload: '{tag_dec[:100]}'",
                    tags=["owasp:llm01"],
                    cwe_ids=["CWE-176"],
                    remediation="Strip or decode Unicode tag characters.",
                ))

        if self._check_variation_selectors and detect_variation_selectors(prompt):
            findings.append(Finding.firewall_input(
                rule_id="FIREWALL-INPUT-022",
                title="Emoji variation selector steganography",
                description="Variation selectors used to embed hidden bit-encoded text.",
                severity=Severity.MEDIUM,
                target="<prompt>",
                evidence="Variation selectors found",
                tags=["owasp:llm01"],
                cwe_ids=["CWE-176"],
                remediation="Strip variation selector characters.",
            ))

        if self._check_zalgo and detect_zalgo(prompt):
            findings.append(Finding.firewall_input(
                rule_id="FIREWALL-INPUT-023",
                title="Zalgo text / stacked combining marks",
                description="Excessive combining marks — hidden payload or rendering attack.",
                severity=Severity.MEDIUM,
                target="<prompt>",
                evidence="Stacked combining marks detected",
                tags=["owasp:llm01"],
                cwe_ids=["CWE-176"],
                remediation="Strip excessive combining marks before processing.",
            ))

        if self._check_fullwidth and FULLWIDTH_PATTERN.search(prompt):
            fw = normalize_fullwidth(prompt)
            if fw != prompt:
                decoded_texts.append(("fullwidth_normalized", fw))

        if self._check_math_unicode:
            math = normalize_math_unicode(prompt)
            if math != prompt:
                decoded_texts.append(("math_unicode_normalized", math))

        if self._check_superscript:
            sup = normalize_superscript_subscript(prompt)
            if sup != prompt:
                decoded_texts.append(("superscript_normalized", sup))

        if self._check_rot47:
            decoded_texts.extend(try_rot47(prompt))
        if self._check_rot18:
            r18 = apply_rot18(prompt)
            if r18 != prompt:
                decoded_texts.append(("rot18", r18))
        if self._check_atbash:
            ab = apply_atbash(prompt)
            if ab != prompt:
                decoded_texts.append(("atbash", ab))
        if self._check_leet and is_likely_leet(prompt):
            leet = normalize_leet(prompt)
            if leet != prompt:
                decoded_texts.append(("leetspeak", leet))
        if self._check_hex_escape:
            decoded_texts.extend(try_hex_escape(prompt))

        if self._check_brainfuck and detect_brainfuck(prompt):
            findings.append(Finding.firewall_input(
                rule_id="FIREWALL-INPUT-024",
                title="Brainfuck / esoteric language payload",
                description="Brainfuck-like chars used to bypass text filters.",
                severity=Severity.MEDIUM,
                target="<prompt>",
                evidence="Brainfuck-like pattern detected",
                tags=["owasp:llm01"],
                cwe_ids=["CWE-838"],
                remediation="Detect and block esoteric language payloads.",
            ))

        if self._check_morse and detect_morse(prompt):
            m = decode_morse(prompt)
            if m:
                decoded_texts.append(("morse", m))

        # Layer-3 decoders
        if self._check_base32:
            decoded_texts.extend(try_base32(prompt))
        if self._check_base85:
            decoded_texts.extend(try_base85(prompt))
        if self._check_html_entity:
            decoded_texts.extend(try_html_entity_decode(prompt))
        if self._check_quoted_printable:
            decoded_texts.extend(try_quoted_printable(prompt))
        if self._check_caesar_brute:
            decoded_texts.extend(caesar_brute(prompt))

        # Pre-compute injection keywords already visible in the original prompt
        # (plain English words like "system" in "operating system" must not fire as
        # encoded injection when the leet-normaliser changes unrelated digits/symbols).
        _orig_norm = normalize_unicode(prompt)
        _original_visible_kws: set[str] = set()
        for _kw in INJECTION_INDICATORS:
            _kl = _kw.lower()
            _ol = _orig_norm.lower()
            if len(_kl) <= 5:
                if re.search(r'\b' + re.escape(_kl) + r'\b', _ol):
                    _original_visible_kws.add(_kl)
            else:
                if _kl in _ol:
                    _original_visible_kws.add(_kl)

        # 3. Check every decoded variant
        seen: set[str] = set()
        for enc_name, decoded in decoded_texts:
            if decoded in seen:
                continue
            seen.add(decoded)
            norm = normalize_unicode(decoded)

            kw = check_injection(norm)
            if kw and kw.lower() not in _original_visible_kws:
                findings.append(Finding.firewall_input(
                    rule_id="FIREWALL-INPUT-005",
                    title=f"Encoded prompt injection ({enc_name})",
                    description=f"{enc_name}-encoded text decodes to '{kw}'.",
                    severity=Severity.HIGH,
                    target="<prompt>",
                    evidence=f"enc={enc_name}, decoded='{decoded[:200]}', kw='{kw}'",
                    tags=["owasp:llm01", "avid-effect:security:S0403"],
                    cwe_ids=["CWE-838"],
                    remediation="Decode all known encodings before injection detection.",
                ))

            rs = detect_reverse_shell(norm)
            if rs:
                findings.append(Finding.firewall_input(
                    rule_id="FIREWALL-INPUT-030",
                    title=f"Encoded reverse shell payload ({enc_name})",
                    description=f"{enc_name} decoded to reverse shell command.",
                    severity=Severity.CRITICAL,
                    target="<prompt>",
                    evidence=f"enc={enc_name}, shell='{rs}'",
                    tags=["owasp:llm01", "owasp:llm02"],
                    cwe_ids=["CWE-78", "CWE-838"],
                    remediation="Block all inputs containing encoded command execution.",
                ))

            ws = detect_web_shell(norm)
            if ws:
                findings.append(Finding.firewall_input(
                    rule_id="FIREWALL-INPUT-031",
                    title=f"Encoded web shell payload ({enc_name})",
                    description=f"{enc_name} decoded to web shell pattern.",
                    severity=Severity.CRITICAL,
                    target="<prompt>",
                    evidence=f"enc={enc_name}, shell='{ws}'",
                    tags=["owasp:llm01", "owasp:llm02"],
                    cwe_ids=["CWE-94", "CWE-838"],
                    remediation="Block all inputs containing encoded web shell patterns.",
                ))

        if not findings:
            return ScanResult(sanitized=prompt, action=ScanAction.PASS, risk_score=0.0)

        return ScanResult(
            sanitized=prompt,
            action=ScanAction.BLOCK,
            risk_score=0.9,
            findings=findings,
        )

    # ── Backward-compat aliases ──────────────────────────────────────────

    def _is_meaningful_text(self, text: str) -> bool:
        return is_meaningful(text)

    def _check_for_injection(self, text: str) -> Optional[str]:
        return check_injection(text)

    def _try_base64_decode(self, text: str) -> list[tuple[str, str]]:
        return try_base64(text, self._min_length)

    def _try_hex_decode(self, text: str) -> list[tuple[str, str]]:
        return try_hex(text, self._min_length)

    def _try_rot13_decode(self, text: str) -> list[tuple[str, str]]:
        return try_rot13(text)

    def _try_url_decode(self, text: str) -> list[tuple[str, str]]:
        return try_url_decode(text)

    def _try_hex_escape_decode(self, text: str) -> list[tuple[str, str]]:
        return try_hex_escape(text)

    def _try_rot47_decode(self, text: str) -> list[tuple[str, str]]:
        return try_rot47(text)
