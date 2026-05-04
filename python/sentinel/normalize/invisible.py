"""Invisible / format character stripping.

Removes zero-width spaces, bidi controls, word joiners, tag-block
characters, and other ``Cf``-category codepoints that attackers use to
hide payloads in otherwise legitimate text.
"""

from __future__ import annotations

import re

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

_INVISIBLE_PATTERN: re.Pattern = re.compile(
    "[" + "".join(re.escape(chr(cp)) for cp in sorted(_INVISIBLE_CODEPOINTS)) + "]"
    r"|\uE0000-\uE007F",
    re.UNICODE,
)

_CF_STRIP_PATTERN: re.Pattern = re.compile(
    r"[\u00ad\u0600-\u0605\u061c\u06dd\u070f\u08e2\u180e"
    r"\u200b-\u200f\u202a-\u202e\u2060-\u2064\u2066-\u206f"
    r"\ufeff\ufff9-\ufffb"
    r"\U000110bd\U000110cd\U00013430-\U0001343f"
    r"\U0001bca0-\U0001bca3\U0001d173-\U0001d17a"
    r"\U000e0001\U000e0020-\U000e007f]",
    re.UNICODE,
)


def strip_invisible(text: str) -> str:
    """Return *text* with invisible / format characters removed.

    Preserves ``\\t``, ``\\n``, ``\\r`` and regular whitespace.
    Idempotent and deterministic. Uses compiled regex for O(n) C-speed
    instead of a Python character loop.
    """
    if not text:
        return text
    return _CF_STRIP_PATTERN.sub("", text)
