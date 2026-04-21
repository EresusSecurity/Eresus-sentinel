"""Confusable folding for Cyrillic / Greek / look-alike codepoints.

Collapses a curated set of homoglyph characters onto their ASCII Latin
equivalents so that ``reаd_file`` (Cyrillic а) matches ``read_file``
after normalization. Not a full UTS #39 confusables table — a focused
mapping of the high-hit characters used in real bypass attempts.
"""

from __future__ import annotations


_CONFUSABLE_MAP: dict[str, str] = {
    # Cyrillic → Latin
    "а": "a", "А": "A",
    "е": "e", "Е": "E",
    "о": "o", "О": "O",
    "р": "p", "Р": "P",
    "с": "c", "С": "C",
    "у": "y", "У": "Y",
    "х": "x", "Х": "X",
    "і": "i", "І": "I",
    "ј": "j", "Ј": "J",
    "ԁ": "d", "һ": "h", "ӏ": "l",
    "ѕ": "s", "Ѕ": "S",
    "в": "B", "В": "B",
    "к": "k", "К": "K",
    "м": "M", "М": "M",
    "т": "T", "Т": "T",
    "н": "H", "Н": "H",
    "Ь": "b",
    # Greek → Latin
    "Α": "A", "Β": "B", "Ε": "E", "Ζ": "Z", "Η": "H", "Ι": "I", "Κ": "K",
    "Μ": "M", "Ν": "N", "Ο": "O", "Ρ": "P", "Τ": "T", "Υ": "Y", "Χ": "X",
    "ο": "o", "ρ": "p", "ν": "v",
}


def fold_confusables(text: str) -> str:
    """Return *text* with curated Cyrillic / Greek look-alikes folded
    to their ASCII Latin equivalents. Non-confusable characters pass
    through unchanged. ASCII-only input is returned verbatim.
    """
    if not text:
        return text
    if text.isascii():
        return text
    return "".join(_CONFUSABLE_MAP.get(ch, ch) for ch in text)
