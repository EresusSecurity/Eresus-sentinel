"""
Encoding attack scanner — pure decode functions (stateless, no I/O).

All functions take a ``str`` and return decoded ``str | None``.
Import from here; never import directly from ``encoding.py``.
"""

from __future__ import annotations

import base64
import binascii
import html
import quopri
import re
import unicodedata
from typing import Optional
from urllib.parse import unquote as _url_unquote

from sentinel.firewall.input._enc_tables import (
    ATBASH_TABLE,
    BASE32_PATTERN,
    BASE64_PATTERN,
    BASE85_PATTERN,
    CAESAR_TABLES,
    CONFUSABLES,
    HEX_ESCAPE_PATTERN,
    HEX_PATTERN,
    HEX_SPACE_PATTERN,
    HTML_ENTITY_PATTERN,
    LEET_MAP,
    MATH_UNICODE_TO_ASCII,
    MORSE_TO_CHAR,
    QUOTED_PRINTABLE_PATTERN,
    ROT13_TABLE,
    ROT18_TABLE,
    ROT47_TABLE,
    ROT5_TABLE,
    SUPERSCRIPT_MAP,
    UNICODE_TAG_DECODE_PATTERN,
    UNICODE_TAG_PATTERN,
    ZERO_WIDTH_PATTERN,
)


# ─────────────────────────────────────────────────────────────────────────────
# Helpers
# ─────────────────────────────────────────────────────────────────────────────

def is_meaningful(text: str, min_len: int = 5, ratio: float = 0.4) -> bool:
    """Return True if *text* contains enough alphabetic content to be real text."""
    if not text or len(text) < min_len:
        return False
    letters = sum(1 for c in text if c.isalpha())
    return letters / len(text) > ratio


# ─────────────────────────────────────────────────────────────────────────────
# Unicode normalisers
# ─────────────────────────────────────────────────────────────────────────────

def normalize_unicode(text: str) -> str:
    """NFKC + confusable map + strip Unicode tag characters."""
    normalized = unicodedata.normalize("NFKC", text)
    result = [CONFUSABLES.get(ch, ch) for ch in normalized]
    cleaned = "".join(result)
    return UNICODE_TAG_PATTERN.sub("", cleaned)


def normalize_fullwidth(text: str) -> str:
    """Map full-width Latin/ASCII (U+FF01–U+FF5E) back to ASCII."""
    result = []
    for ch in text:
        cp = ord(ch)
        if 0xFF01 <= cp <= 0xFF5E:
            result.append(chr(cp - 0xFEE0))
        elif cp == 0xFF00:
            result.append(" ")
        else:
            result.append(ch)
    return "".join(result)


def normalize_math_unicode(text: str) -> str:
    """Map math bold/italic/fraktur/monospace Unicode (U+1D400–U+1D7FF) to ASCII."""
    if not text:
        return text
    return "".join(MATH_UNICODE_TO_ASCII.get(ord(ch), ch) for ch in text)


def normalize_superscript_subscript(text: str) -> str:
    """Map superscript/subscript Unicode chars to their ASCII equivalents."""
    return "".join(SUPERSCRIPT_MAP.get(ord(ch), ch) for ch in text)


def normalize_leet(text: str) -> str:
    """Map leet-speak digit/symbol substitutions to ASCII letters.

    ``1gn0r3 4ll pr3v10us`` → ``ignore all previous``
    """
    return "".join(LEET_MAP.get(ch, ch) for ch in text)


def is_likely_leet(text: str) -> bool:
    """Return True if *text* contains ≥3 leet substitution characters."""
    return sum(1 for c in text if c in LEET_MAP) >= 3


# ─────────────────────────────────────────────────────────────────────────────
# ROT-family decoders
# ─────────────────────────────────────────────────────────────────────────────

def apply_rot13(text: str) -> str:
    return text.translate(ROT13_TABLE)


def apply_rot47(text: str) -> str:
    return text.translate(ROT47_TABLE)


def apply_rot18(text: str) -> str:
    return text.translate(ROT18_TABLE)


def apply_rot5(text: str) -> str:
    return text.translate(ROT5_TABLE)


def apply_atbash(text: str) -> str:
    return text.translate(ATBASH_TABLE)


_COMMON_WORDS = frozenset({
    "the", "and", "for", "are", "but", "not", "you", "all", "can", "had",
    "her", "was", "one", "our", "out", "has", "his", "how", "its", "may",
    "new", "now", "old", "see", "way", "who", "did", "get", "let", "say",
    "she", "too", "use", "from", "have", "this", "that", "with", "will",
    "your", "they", "been", "some", "what", "when", "make", "like", "just",
    "over", "such", "take", "into", "most", "than", "them", "very", "after",
    "also", "know", "back", "only", "come", "made", "find", "here", "thing",
    "many", "well", "about", "would", "there", "their", "which", "could",
    "other", "should", "ignore", "system", "prompt", "instruction", "previous",
    "forget", "override", "disregard", "bypass", "pretend", "jailbreak",
})


def _has_english_words(text: str, min_words: int = 2) -> bool:
    """Return True if text contains at least *min_words* common English words."""
    words = re.findall(r"[a-zA-Z]{3,}", text.lower())
    return sum(1 for w in words if w in _COMMON_WORDS) >= min_words


def caesar_brute(text: str) -> list[tuple[str, str]]:
    """Try all 25 Caesar shifts and return those producing meaningful text.

    Returns ``[(label, decoded), ...]`` e.g. ``[("caesar_rot7", "ignore all")]``.
    Only returns results where the decoded text contains recognisable English
    words — pure gibberish with high alphabetic ratio is filtered out.
    """
    results: list[tuple[str, str]] = []
    for n, table in enumerate(CAESAR_TABLES, start=1):
        decoded = text.translate(table)
        if decoded != text and is_meaningful(decoded) and _has_english_words(decoded):
            results.append((f"caesar_rot{n}", decoded))
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Base-N decoders
# ─────────────────────────────────────────────────────────────────────────────

def try_base64(text: str, min_len: int = 20) -> list[tuple[str, str]]:
    """Extract and decode base64 / base64url blobs."""
    results: list[tuple[str, str]] = []
    seen: set[str] = set()
    for match in BASE64_PATTERN.finditer(text):
        encoded = match.group()
        if len(encoded) < min_len or encoded in seen:
            continue
        seen.add(encoded)
        for decoder, label in [
            (base64.b64decode, "base64"),
            (base64.urlsafe_b64decode, "base64url"),
        ]:
            try:
                padded = encoded + "=" * (-len(encoded) % 4)
                decoded = decoder(padded).decode("utf-8", errors="replace")
                if is_meaningful(decoded):
                    results.append((label, decoded))
                    break
            except Exception:
                continue
    return results


def try_base32(text: str) -> list[tuple[str, str]]:
    """Extract and decode base32 blobs."""
    results: list[tuple[str, str]] = []
    for match in BASE32_PATTERN.finditer(text):
        encoded = match.group()
        try:
            padded = encoded + "=" * (-len(encoded) % 8)
            decoded = base64.b32decode(padded, casefold=True).decode("utf-8", errors="replace")
            if is_meaningful(decoded):
                results.append(("base32", decoded))
        except Exception:
            continue
    return results


def try_base85(text: str) -> list[tuple[str, str]]:
    """Attempt ascii85 / base85 decode on candidate blobs."""
    results: list[tuple[str, str]] = []
    for match in BASE85_PATTERN.finditer(text):
        blob = match.group()
        if len(blob) < 20:
            continue
        for decoder, label in [
            (base64.a85decode, "ascii85"),
            (base64.b85decode, "base85"),
        ]:
            try:
                decoded = decoder(blob.encode()).decode("utf-8", errors="replace")
                if is_meaningful(decoded):
                    results.append((label, decoded))
                    break
            except Exception:
                continue
    return results


def try_hex(text: str, min_len: int = 20) -> list[tuple[str, str]]:
    """Decode 0x-prefixed and raw hex blobs."""
    results: list[tuple[str, str]] = []
    for match in HEX_PATTERN.finditer(text):
        encoded = match.group()
        if encoded.startswith("0x"):
            encoded = encoded[2:]
        if len(encoded) < min_len or len(encoded) % 2:
            continue
        try:
            decoded = binascii.unhexlify(encoded).decode("utf-8", errors="replace")
            if is_meaningful(decoded):
                results.append(("hex", decoded))
        except Exception:
            continue
    return results


def try_hex_escape(text: str) -> list[tuple[str, str]]:
    r"""Decode C-style ``\x41\x42`` and space-delimited ``41 42 43`` hex."""
    results: list[tuple[str, str]] = []
    # \x41\x42 style
    for match in HEX_ESCAPE_PATTERN.finditer(text):
        raw = match.group().replace("\\x", "")
        try:
            decoded = bytes.fromhex(raw).decode("utf-8", errors="replace")
            if is_meaningful(decoded):
                results.append(("hex_escape", decoded))
        except Exception:
            pass
    # "41 42 43" space-delimited
    for match in HEX_SPACE_PATTERN.finditer(text):
        raw = match.group().replace(" ", "")
        if len(raw) % 2:
            continue
        try:
            decoded = bytes.fromhex(raw).decode("utf-8", errors="replace")
            if is_meaningful(decoded):
                results.append(("hex_space", decoded))
        except Exception:
            pass
    return results


# ─────────────────────────────────────────────────────────────────────────────
# Text-encoding decoders
# ─────────────────────────────────────────────────────────────────────────────

def try_url_decode(text: str) -> list[tuple[str, str]]:
    """Decode URL percent-encoding, including double/triple encoding."""
    if "%" not in text:
        return []
    results: list[tuple[str, str]] = []
    current = text
    label_parts = ["url"]
    for _ in range(3):  # up to triple encoding
        decoded = _url_unquote(current)
        if decoded == current:
            break
        current = decoded
        label_parts.append("decoded")
        if is_meaningful(decoded):
            results.append(("_".join(label_parts), decoded))
    return results


def try_html_entity_decode(text: str) -> list[tuple[str, str]]:
    """Decode HTML entities: ``&#105;`` ``&#x69;`` ``&amp;`` → plaintext."""
    if not HTML_ENTITY_PATTERN.search(text):
        return []
    try:
        decoded = html.unescape(text)
        if decoded != text and is_meaningful(decoded):
            return [("html_entity", decoded)]
    except Exception:
        pass
    return []


def try_quoted_printable(text: str) -> list[tuple[str, str]]:
    """Decode Quoted-Printable encoding (``=69=67=6E=6F=72=65`` → ``ignore``)."""
    if not QUOTED_PRINTABLE_PATTERN.search(text):
        return []
    try:
        decoded = quopri.decodestring(text.encode()).decode("utf-8", errors="replace")
        if decoded != text and is_meaningful(decoded):
            return [("quoted_printable", decoded)]
    except Exception:
        pass
    return []


def try_rot13(text: str) -> list[tuple[str, str]]:
    decoded = apply_rot13(text)
    if decoded != text and _looks_rot_encoded(text, decoded):
        return [("rot13", decoded)]
    return []


def _looks_rot_encoded(original: str, decoded: str) -> bool:
    return _suspicious_keyword_delta(original, decoded) >= 2


def _suspicious_keyword_delta(original: str, decoded: str) -> int:
    from sentinel.firewall.input._enc_tables import INJECTION_INDICATORS

    left = original.lower()
    right = decoded.lower()
    return sum(1 for kw in INJECTION_INDICATORS if kw.lower() in right and kw.lower() not in left)


def try_rot47(text: str) -> list[tuple[str, str]]:
    decoded = apply_rot47(text)
    if decoded != text and is_meaningful(decoded) and _suspicious_keyword_delta(text, decoded) >= 2:
        return [("rot47", decoded)]
    return []


def decode_unicode_tags(text: str) -> Optional[str]:
    """Decode Unicode Tags block (U+E0020–U+E007E) used for invisible text."""
    matches = UNICODE_TAG_DECODE_PATTERN.findall(text)
    if not matches:
        return None
    parts = ["".join(chr(ord(c) - 0xE0000) for c in run) for run in matches]
    result = " ".join(parts).strip()
    return result if len(result) >= 3 else None


def decode_morse(text: str) -> Optional[str]:
    """Decode Morse code if the text is a valid Morse string."""
    stripped = text.strip()
    groups = re.split(r"\s+", stripped)
    if len(groups) < 5:
        return None
    decoded = []
    for group in groups:
        ch = MORSE_TO_CHAR.get(group)
        if ch is None:
            return None
        decoded.append(ch)
    result = "".join(decoded).strip()
    return result if len(result) >= 3 else None


def strip_zero_width(text: str) -> str:
    """Remove zero-width chars used in token bombs / steganography."""
    return ZERO_WIDTH_PATTERN.sub("", text)


# ─────────────────────────────────────────────────────────────────────────────
# Multi-layer decode pipeline
# ─────────────────────────────────────────────────────────────────────────────

MAX_DECODE_LAYERS = 3
_MAX_DECODE_BRANCHES = 10
_MAX_DECODE_RESULTS = 50


def multi_layer_decode(text: str) -> list[tuple[str, str]]:
    """Peel up to MAX_DECODE_LAYERS of stacked encodings.

    Returns ``[(chain_label, decoded_text), ...]``.
    Branch count and total results are capped to prevent exponential
    memory/CPU growth on adversarial inputs.
    """
    results: list[tuple[str, str]] = []
    current_texts = [("", text)]

    for _layer in range(MAX_DECODE_LAYERS):
        next_texts: list[tuple[str, str]] = []
        for chain, txt in current_texts:
            for label, decoded in try_base64(txt) + try_hex(txt) + try_rot13(txt):
                full_label = f"{chain}>{label}" if chain else label
                if is_meaningful(decoded) and decoded != txt:
                    results.append((full_label, decoded))
                    next_texts.append((full_label, decoded))
                if len(results) >= _MAX_DECODE_RESULTS:
                    return results
        if not next_texts:
            break
        current_texts = next_texts[:_MAX_DECODE_BRANCHES]

    return results


__all__ = [
    "is_meaningful",
    "normalize_unicode", "normalize_fullwidth", "normalize_math_unicode",
    "normalize_superscript_subscript", "normalize_leet", "is_likely_leet",
    "apply_rot13", "apply_rot47", "apply_rot18", "apply_rot5", "apply_atbash",
    "caesar_brute",
    "try_base64", "try_base32", "try_base85", "try_hex", "try_hex_escape",
    "try_url_decode", "try_html_entity_decode", "try_quoted_printable",
    "try_rot13", "try_rot47",
    "decode_unicode_tags", "decode_morse", "strip_zero_width",
    "multi_layer_decode", "MAX_DECODE_LAYERS",
]
