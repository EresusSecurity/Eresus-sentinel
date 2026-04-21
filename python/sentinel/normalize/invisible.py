"""Invisible / format character stripping.

Removes zero-width spaces, bidi controls, word joiners, tag-block
characters, and other ``Cf``-category codepoints that attackers use to
hide payloads in otherwise legitimate text.
"""

from __future__ import annotations

import unicodedata


_INVISIBLE_CODEPOINTS: frozenset[int] = frozenset({
    0x00AD,                                          # soft hyphen
    0x200B, 0x200C, 0x200D, 0x200E, 0x200F,          # ZWSP/ZWNJ/ZWJ/LRM/RLM
    0x202A, 0x202B, 0x202C, 0x202D, 0x202E,          # bidi embed/override
    0x2060, 0x2061, 0x2062, 0x2063, 0x2064,          # word joiner + invisibles
    0x2066, 0x2067, 0x2068, 0x2069,                  # bidi isolates
    0xFEFF,                                          # BOM
    0x180E,                                          # mongolian vowel separator
    0x034F,                                          # combining grapheme joiner
})

_INVISIBLE_TAG_RANGE: range = range(0xE0000, 0xE0080)


def strip_invisible(text: str) -> str:
    """Return *text* with invisible / format characters removed.

    Preserves ``\\t``, ``\\n``, ``\\r`` and regular whitespace.
    Idempotent and deterministic.
    """
    if not text:
        return text

    out: list[str] = []
    for ch in text:
        cp = ord(ch)
        if cp in _INVISIBLE_CODEPOINTS or cp in _INVISIBLE_TAG_RANGE:
            continue
        if unicodedata.category(ch) == "Cf":
            continue
        out.append(ch)
    return "".join(out)
