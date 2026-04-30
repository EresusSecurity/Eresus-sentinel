"""
Encoding attack scanner — translation tables and constant mappings.

All cipher/alphabet tables, leet maps, math-Unicode maps and regex
patterns are centralised here so they are compiled once at import time
and reused across decoders and detectors.
"""

from __future__ import annotations

import re

# ── Caesar / ROT ciphers ───────────────────────────────────────────────────

ROT13_TABLE = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm",
)

# ROT47 — printable ASCII 33-126 rotated by 47
ROT47_TABLE = str.maketrans(
    "".join(chr(c) for c in range(33, 127)),
    "".join(chr(33 + (c - 33 + 47) % 94) for c in range(33, 127)),
)

# ROT18 — ROT13 on letters + ROT5 on digits
ROT18_TABLE = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789",
    "NOPQRSTUVWXYZABCDEFGHIJKLMnopqrstuvwxyzabcdefghijklm5678901234",
)

# ROT5 — digits only
ROT5_TABLE = str.maketrans("0123456789", "5678901234")

# Atbash — A↔Z reversal
ATBASH_TABLE = str.maketrans(
    "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz",
    "ZYXWVUTSRQPONMLKJIHGFEDCBAzyxwvutsrqponmlkjihgfedcba",
)

# Pre-built Caesar tables for all 25 non-trivial shifts (ROT-1 … ROT-25)
_UPPER = "ABCDEFGHIJKLMNOPQRSTUVWXYZ"
_LOWER = "abcdefghijklmnopqrstuvwxyz"
CAESAR_TABLES: list[bytes] = [
    str.maketrans(
        _UPPER + _LOWER,
        _UPPER[n:] + _UPPER[:n] + _LOWER[n:] + _LOWER[:n],
    )
    for n in range(1, 26)
]

# ── Leet-speak substitution map ────────────────────────────────────────────
LEET_MAP: dict[str, str] = {
    "0": "o", "1": "i", "3": "e", "4": "a", "5": "s",
    "6": "g", "7": "t", "8": "b", "@": "a", "!": "i",
    "|": "i", "$": "s", "+": "t",
}
LEET_TRIGGER_PATTERN = re.compile(r"[01345678@!|$+]")

# ── Unicode confusable mappings ────────────────────────────────────────────
CONFUSABLES: dict[str, str] = {
    # Cyrillic homoglyphs
    "\u0406": "I", "\u0410": "A", "\u0412": "B", "\u0415": "E",
    "\u041a": "K", "\u041c": "M", "\u041d": "H", "\u041e": "O",
    "\u0420": "P", "\u0421": "C", "\u0422": "T", "\u0425": "X",
    "\u0430": "a", "\u0435": "e", "\u043e": "o", "\u0440": "p",
    "\u0441": "c", "\u0443": "y", "\u0445": "x",
    # Greek homoglyphs
    "\u03b1": "a", "\u03b2": "b", "\u03b5": "e", "\u03b7": "n",
    "\u03bf": "o", "\u03c1": "p", "\u03c5": "u", "\u03c7": "x",
    "\u0391": "A", "\u0392": "B", "\u0395": "E", "\u0396": "Z",
    "\u0397": "H", "\u0399": "I", "\u039a": "K", "\u039c": "M",
    "\u039d": "N", "\u039f": "O", "\u03a1": "P", "\u03a4": "T",
    "\u03a5": "Y", "\u03a7": "X",
    # Roman numerals
    "\u2160": "I",  "\u2161": "II", "\u2164": "V",  "\u2169": "X",
    "\u216c": "L",  "\u216d": "C",  "\u216e": "D",  "\u216f": "M",
    # Full-width
    "\uff21": "A", "\uff22": "B", "\uff23": "C", "\uff49": "i",
    "\uff47": "g", "\uff4e": "n", "\uff4f": "o", "\uff52": "r",
    "\uff45": "e",
    # Dotless i / Turkish
    "\u0131": "i",
    # Latin extended look-alikes
    "\u00f8": "o",  # ø → o
    "\u0142": "l",  # ł → l
    "\u017f": "s",  # ſ → s  (long s)
    "\u00df": "ss", # ß → ss
}

# ── Morse code table ───────────────────────────────────────────────────────
MORSE_TO_CHAR: dict[str, str] = {
    ".-": "A",   "-...": "B",  "-.-.": "C",  "-..": "D",  ".": "E",
    "..-.": "F", "--.": "G",   "....": "H",  "..": "I",   ".---": "J",
    "-.-": "K",  ".-..": "L",  "--": "M",    "-.": "N",   "---": "O",
    ".--.": "P", "--.-": "Q",  ".-.": "R",   "...": "S",  "-": "T",
    "..-": "U",  "...-": "V",  ".--": "W",   "-..-": "X", "-.--": "Y",
    "--..": "Z", ".----": "1", "..---": "2", "...--": "3",
    "....-": "4", ".....": "5", "-....": "6", "--...": "7",
    "---..": "8", "----.": "9", "-----": "0", "/": " ", "": " ",
}

# ── Mathematical Unicode block (U+1D400–U+1D7FF) ──────────────────────────

def _build_math_unicode_map() -> dict[int, str]:
    mapping: dict[int, str] = {}
    offsets = [
        (0x1D400, "A", 26), (0x1D41A, "a", 26), (0x1D434, "A", 26),
        (0x1D44E, "a", 26), (0x1D468, "A", 26), (0x1D482, "a", 26),
        (0x1D49C, "A", 26), (0x1D4B6, "a", 26), (0x1D4D0, "A", 26),
        (0x1D4EA, "a", 26), (0x1D504, "A", 26), (0x1D51E, "a", 26),
        (0x1D538, "A", 26), (0x1D552, "a", 26), (0x1D56C, "A", 26),
        (0x1D586, "a", 26), (0x1D5A0, "A", 26), (0x1D5BA, "a", 26),
        (0x1D5D4, "A", 26), (0x1D5EE, "a", 26), (0x1D608, "A", 26),
        (0x1D622, "a", 26), (0x1D63C, "A", 26), (0x1D656, "a", 26),
        (0x1D670, "A", 26), (0x1D68A, "a", 26),
        # Digits
        (0x1D7CE, "0", 10), (0x1D7D8, "0", 10), (0x1D7E2, "0", 10),
        (0x1D7EC, "0", 10), (0x1D7F6, "0", 10),
    ]
    for start, base, count in offsets:
        for i in range(count):
            mapping[start + i] = chr(ord(base) + i)
    return mapping


MATH_UNICODE_TO_ASCII: dict[int, str] = _build_math_unicode_map()

# ── Superscript / Subscript map ────────────────────────────────────────────
SUPERSCRIPT_MAP: dict[int, str] = {
    0x00B2: "2", 0x00B3: "3", 0x00B9: "1",
    0x2070: "0", 0x2074: "4", 0x2075: "5",
    0x2076: "6", 0x2077: "7", 0x2078: "8", 0x2079: "9",
    0x207A: "+", 0x207B: "-", 0x207C: "=", 0x207D: "(",
    0x207E: ")", 0x207F: "n",
    0x2080: "0", 0x2081: "1", 0x2082: "2", 0x2083: "3",
    0x2084: "4", 0x2085: "5", 0x2086: "6", 0x2087: "7",
    0x2088: "8", 0x2089: "9",
}

# ── Script ranges for mixed-script detection ───────────────────────────────
LATIN_RANGE: frozenset[int] = frozenset(range(0x0041, 0x024F + 1))
CYRILLIC_RANGE: frozenset[int] = frozenset(range(0x0400, 0x04FF + 1))
GREEK_RANGE: frozenset[int] = frozenset(range(0x0370, 0x03FF + 1))
ARABIC_RANGE: frozenset[int] = frozenset(range(0x0600, 0x06FF + 1))
HEBREW_RANGE: frozenset[int] = frozenset(range(0x0590, 0x05FF + 1))

# ── Compiled regex patterns ────────────────────────────────────────────────
BASE64_PATTERN = re.compile(r"[A-Za-z0-9+/]{20,}={0,2}", re.MULTILINE)
HEX_PATTERN = re.compile(r"(?:0x)?[0-9a-fA-F]{20,}", re.MULTILINE)
UNICODE_TAG_PATTERN = re.compile(r"[\U000E0001-\U000E007F]+")
UNICODE_TAG_DECODE_PATTERN = re.compile(r"[\U000E0020-\U000E007E]+")
ZERO_WIDTH_PATTERN = re.compile(r"[\u200B\u200C\u200D\u2060\uFEFF\u00AD]+")
VARIATION_SELECTOR_PATTERN = re.compile(
    r"[\uFE00-\uFE0F]|[\U000E0100-\U000E01EF]"
)
FULLWIDTH_PATTERN = re.compile(r"[\uFF01-\uFF60\uFF61-\uFFEF]{3,}")
BRAINFUCK_PATTERN = re.compile(r"[+\-\[\].,<>]{8,}")
MORSE_PATTERN = re.compile(r"(?:[.\-]{1,5}\s){5,}")
ZALGO_PATTERN = re.compile(
    r"(?:[\u0300-\u036F\u1DC0-\u1DFF\u20D0-\u20FF\uFE20-\uFE2F]{3,}){3,}"
)
HEX_ESCAPE_PATTERN = re.compile(r"(?:\\x[0-9a-fA-F]{2}){4,}")
HEX_SPACE_PATTERN = re.compile(r"\b(?:[0-9A-Fa-f]{2} ){5,}[0-9A-Fa-f]{2}\b")
HTML_ENTITY_PATTERN = re.compile(
    r"(?:&#x[0-9a-fA-F]{2,4};|&#[0-9]{2,5};|&[a-zA-Z]{2,8};){3,}"
)
QUOTED_PRINTABLE_PATTERN = re.compile(r"(?:=[0-9A-Fa-f]{2}){4,}")
BASE32_PATTERN = re.compile(r"[A-Z2-7]{16,}={0,6}", re.MULTILINE)
BASE85_PATTERN = re.compile(r"[0-9A-Za-z!#$%&()*+\-;<=>?@^_`{|}~]{20,}")

# ── Injection indicator keywords ───────────────────────────────────────────
# Used by decoders to check decoded plaintext for attack patterns.
INJECTION_INDICATORS: list[str] = [
    # Instruction override
    "ignore", "disregard", "forget", "override", "bypass",
    # System / code execution
    "system", "exec", "eval", "import", "os.system",
    "subprocess", "__import__", "__reduce__",
    # Prompt manipulation
    "prompt", "instruction", "jailbreak", "DAN",
    "pretend", "roleplay", "persona",
    # Reverse shell / backdoor (new)
    "bash -i", "nc -e", "ncat", "mkfifo",
    "reverse_shell", "shell_exec", "passthru",
    "/bin/sh", "/bin/bash", "cmd.exe",
    "powershell", "wget http", "curl http",
]

__all__ = [
    "ROT13_TABLE", "ROT47_TABLE", "ROT18_TABLE", "ROT5_TABLE",
    "ATBASH_TABLE", "CAESAR_TABLES",
    "LEET_MAP", "LEET_TRIGGER_PATTERN",
    "CONFUSABLES",
    "MORSE_TO_CHAR",
    "MATH_UNICODE_TO_ASCII", "SUPERSCRIPT_MAP",
    "LATIN_RANGE", "CYRILLIC_RANGE", "GREEK_RANGE",
    "ARABIC_RANGE", "HEBREW_RANGE",
    "BASE64_PATTERN", "HEX_PATTERN", "UNICODE_TAG_PATTERN",
    "UNICODE_TAG_DECODE_PATTERN", "ZERO_WIDTH_PATTERN",
    "VARIATION_SELECTOR_PATTERN", "FULLWIDTH_PATTERN",
    "BRAINFUCK_PATTERN", "MORSE_PATTERN", "ZALGO_PATTERN",
    "HEX_ESCAPE_PATTERN", "HEX_SPACE_PATTERN",
    "HTML_ENTITY_PATTERN", "QUOTED_PRINTABLE_PATTERN",
    "BASE32_PATTERN", "BASE85_PATTERN",
    "INJECTION_INDICATORS",
]
