"""Encoding-wrapper decoders.

Best-effort extractors for content an attacker may have wrapped in
base64 / hex / rot13 / unicode-escape / URL-encoding / HTML entities.
Each decoder returns candidate decoded strings that passed a printability
filter; callers typically concatenate the original text with the candidates
before running pattern matching.

New in this revision
--------------------
* ``decode_url(text)`` — urllib.parse.unquote (handles %XX and %uXXXX)
* ``decode_html_entities(text)`` — html.unescape
* ``normalize_unicode(text, form)`` — unicodedata.normalize (default: NFKC)
* ``recursive_decode(text, budget)`` — chains decode passes until stable
"""

from __future__ import annotations

import base64
import binascii
import codecs
import html
import re
import unicodedata
import urllib.parse

_BASE64_REGEX = re.compile(r"(?:[A-Za-z0-9+/]{16,}={0,2})")
_HEX_REGEX = re.compile(r"\b(?:[0-9A-Fa-f]{2}){12,}\b")
_PRINTABLE_RATIO_MIN = 0.80


def _looks_printable(s: str) -> bool:
    if not s:
        return False
    printable = sum(1 for c in s if c.isprintable() or c in "\t\n\r")
    return (printable / len(s)) >= _PRINTABLE_RATIO_MIN


def _decode_base64_candidates(text: str, remaining: int) -> list[str]:
    out: list[str] = []
    for match in _BASE64_REGEX.finditer(text):
        if len(out) >= remaining:
            break
        blob = match.group(0)
        pad = "=" * (-len(blob) % 4)
        try:
            decoded = base64.b64decode(blob + pad, validate=False).decode(
                "utf-8", errors="replace"
            )
        except (binascii.Error, ValueError):
            continue
        if _looks_printable(decoded) and len(decoded) >= 4:
            out.append(decoded)
    return out


def _decode_hex_candidates(text: str, remaining: int) -> list[str]:
    out: list[str] = []
    for match in _HEX_REGEX.finditer(text):
        if len(out) >= remaining:
            break
        try:
            decoded = bytes.fromhex(match.group(0)).decode("utf-8", errors="replace")
        except ValueError:
            continue
        if _looks_printable(decoded) and len(decoded) >= 4:
            out.append(decoded)
    return out


_ROT13_SIGNAL_WORDS = (
    "ignore", "system", "password", "execute",
    "override", "reveal", "instruction", "secret",
)


def _decode_rot13_candidate(text: str) -> list[str]:
    try:
        rot = codecs.decode(text, "rot_13")
    except Exception:  # noqa: BLE001
        return []
    if rot == text:
        return []
    low = rot.lower()
    if any(w in low for w in _ROT13_SIGNAL_WORDS):
        return [rot]
    return []


def _decode_unicode_escape_candidate(text: str) -> list[str]:
    if "\\u" not in text and "\\x" not in text:
        return []
    try:
        decoded = codecs.decode(text, "unicode_escape")
    except (UnicodeDecodeError, ValueError):
        return []
    if decoded != text and _looks_printable(decoded):
        return [decoded]
    return []


def decode_common(text: str, max_decode: int = 4) -> list[str]:
    """Return up to *max_decode* candidate decoded strings extracted
    from *text*. Handles base64, hex, rot13, and unicode-escape wraps.
    """
    candidates: list[str] = []

    candidates.extend(_decode_base64_candidates(text, max_decode - len(candidates)))
    if len(candidates) < max_decode:
        candidates.extend(_decode_hex_candidates(text, max_decode - len(candidates)))
    if len(candidates) < max_decode:
        candidates.extend(_decode_rot13_candidate(text))
    if len(candidates) < max_decode:
        candidates.extend(_decode_unicode_escape_candidate(text))

    return candidates[:max_decode]


# ── URL decoding ──────────────────────────────────────────────

def decode_url(text: str) -> str:
    """URL-decode *text* (%XX and %uXXXX).

    Applies two passes to handle double-encoding (e.g. ``%2520`` → ``%20`` → `` ``).
    Returns the most-decoded form that is still printable; falls back to
    single-pass if the double-decoded result becomes non-printable.
    """
    try:
        # Handle %uXXXX (non-standard IE extension used in attacks)
        text = re.sub(
            r"%u([0-9A-Fa-f]{4})",
            lambda m: chr(int(m.group(1), 16)),
            text,
        )
        single = urllib.parse.unquote(text, errors="replace")
        double = urllib.parse.unquote(single, errors="replace")
        if _looks_printable(double):
            return double
        return single
    except Exception:  # noqa: BLE001
        return text


# ── HTML entity decoding ──────────────────────────────────────

def decode_html_entities(text: str) -> str:
    """Unescape HTML entities (``&lt;`` → ``<``, ``&#x41;`` → ``A``, etc.)."""
    try:
        decoded = html.unescape(text)
        return decoded if decoded != text else text
    except Exception:  # noqa: BLE001
        return text


# ── Unicode normalization ─────────────────────────────────────

def normalize_unicode(text: str, form: str = "NFKC") -> str:
    """Apply Unicode normalization to *text*.

    NFKC is the recommended form for security-sensitive matching:
    it maps visually confusable characters (homoglyphs, full-width,
    superscripts) to their canonical ASCII equivalents.

    >>> normalize_unicode("ｉｇｎｏｒｅ")  # full-width → ASCII
    'ignore'
    """
    try:
        return unicodedata.normalize(form, text)
    except Exception:  # noqa: BLE001
        return text


# ── Recursive decode ──────────────────────────────────────────

def recursive_decode(text: str, budget: int = 4) -> str:
    """Iteratively apply all decode passes until the output stabilises.

    Applies the following transforms in each round (order matters):
    1. Unicode NFKC normalization (collapses homoglyphs)
    2. HTML entity decode
    3. URL decode (handles double-encoding)
    4. Unicode-escape decode (\\uXXXX, \\xXX)

    Stops early when two consecutive rounds produce identical output,
    or when *budget* rounds are exhausted.

    Parameters
    ----------
    text:
        Input text to normalise and decode.
    budget:
        Maximum number of decode passes (default 4). Set to 1 for a
        single normalisation pass. Values > 8 are silently capped at 8
        to prevent runaway processing.

    Returns
    -------
    str
        The most-decoded form of the text after up to *budget* passes.
    """
    budget = min(budget, 8)
    for _ in range(budget):
        previous = text
        text = normalize_unicode(text)
        text = decode_html_entities(text)
        text = decode_url(text)
        text = _unicode_escape_single_pass(text)
        if text == previous:
            break
    return text


def _unicode_escape_single_pass(text: str) -> str:
    """Single-pass unicode_escape decode (non-raising)."""
    if "\\u" not in text and "\\x" not in text:
        return text
    try:
        decoded = codecs.decode(text, "unicode_escape")
    except (UnicodeDecodeError, ValueError):
        return text
    return decoded if _looks_printable(decoded) else text

