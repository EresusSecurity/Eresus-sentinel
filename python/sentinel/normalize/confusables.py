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
    # IPA / Phonetic small-caps used in bypass attacks (e.g. ɪɢɴoʀᴇ → ignore)
    "\u026a": "i", "\u0274": "n", "\u0262": "g", "\u0280": "r",
    "\u1d07": "e", "\u1d00": "a", "\u0299": "b", "\u1d04": "c",
    "\u1d05": "d", "\u0493": "f", "\u029c": "h", "\u1d0a": "j",
    "\u1d0b": "k", "\u029f": "l", "\u1d0d": "m", "\u1d0f": "o",
    "\u1d18": "p", "\ua731": "s", "\u1d1b": "t", "\u1d1c": "u",
    "\u1d20": "v", "\u1d21": "w", "\u028f": "y", "\u1d22": "z",
    "\u0251": "a", "\u0253": "b", "\u0254": "o", "\u0257": "d",
    "\u0258": "e", "\u025b": "e", "\u0261": "g", "\u0266": "h",
    "\u0268": "i", "\u0269": "i", "\u029d": "j", "\u026e": "l",
    "\u0271": "m", "\u026f": "m", "\u0273": "n", "\u0275": "o",
    "\u0282": "s", "\u0288": "t", "\u0289": "u", "\u028b": "v",
    "\u028d": "w", "\u0263": "y", "\u0290": "z",
    # Circled uppercase (U+24B6..U+24CF) and lowercase (U+24D0..U+24E9)
    "\u24b6": "A", "\u24b7": "B", "\u24b8": "C", "\u24b9": "D",
    "\u24ba": "E", "\u24bb": "F", "\u24bc": "G", "\u24bd": "H",
    "\u24be": "I", "\u24bf": "J", "\u24c0": "K", "\u24c1": "L",
    "\u24c2": "M", "\u24c3": "N", "\u24c4": "O", "\u24c5": "P",
    "\u24c6": "Q", "\u24c7": "R", "\u24c8": "S", "\u24c9": "T",
    "\u24ca": "U", "\u24cb": "V", "\u24cc": "W", "\u24cd": "X",
    "\u24ce": "Y", "\u24cf": "Z",
    "\u24d0": "a", "\u24d1": "b", "\u24d2": "c", "\u24d3": "d",
    "\u24d4": "e", "\u24d5": "f", "\u24d6": "g", "\u24d7": "h",
    "\u24d8": "i", "\u24d9": "j", "\u24da": "k", "\u24db": "l",
    "\u24dc": "m", "\u24dd": "n", "\u24de": "o", "\u24df": "p",
    "\u24e0": "q", "\u24e1": "r", "\u24e2": "s", "\u24e3": "t",
    "\u24e4": "u", "\u24e5": "v", "\u24e6": "w", "\u24e7": "x",
    "\u24e8": "y", "\u24e9": "z",
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
