"""Encoding-wrapper decoders.

Best-effort extractors for content an attacker may have wrapped in
base64 / hex / rot13 / unicode-escape sequences. Each decoder returns
candidate decoded strings that passed a printability filter; callers
typically concatenate the original text with the candidates before
running pattern matching.
"""

from __future__ import annotations

import base64
import binascii
import codecs
import re


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
