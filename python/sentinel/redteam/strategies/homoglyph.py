"""
Homoglyph Encoding Strategy.

Uses visually similar Unicode characters (homoglyphs) to bypass
"""
from __future__ import annotations

# Map of standard chars to visually similar Unicode characters
HOMOGLYPH_MAP: dict[str, str] = {
    "a": "\u0430",  # Cyrillic а
    "b": "\u0184",  # Latin small letter b with topbar
    "c": "\u0441",  # Cyrillic с
    "d": "\u0501",  # Cyrillic д
    "e": "\u0435",  # Cyrillic е
    "g": "\u0261",  # Latin small letter script g
    "h": "\u04BB",  # Cyrillic һ
    "i": "\u0456",  # Cyrillic і
    "j": "\u0458",  # Cyrillic ј
    "k": "\u03BA",  # Greek kappa
    "l": "\u04CF",  # Cyrillic palochka
    "m": "\uFF4D",  # Fullwidth Latin m
    "n": "\u0578",  # Armenian n
    "o": "\u043E",  # Cyrillic о
    "p": "\u0440",  # Cyrillic р
    "q": "\u051B",  # Cyrillic q-like
    "r": "\u0433",  # Cyrillic г
    "s": "\u0455",  # Cyrillic ѕ
    "t": "\u03C4",  # Greek tau
    "u": "\u03C5",  # Greek upsilon
    "v": "\u03BD",  # Greek nu
    "w": "\u051D",  # Cyrillic w-like
    "x": "\u0445",  # Cyrillic х
    "y": "\u0443",  # Cyrillic у
    "z": "\u017C",  # Latin z with dot above
    "A": "\u0391",  # Greek Alpha
    "B": "\u0412",  # Cyrillic В
    "C": "\u0421",  # Cyrillic С
    "D": "\u13A0",  # Cherokee letter A
    "E": "\u0415",  # Cyrillic Е
    "F": "\u03DC",  # Greek Digamma
    "G": "\u050C",  # Cyrillic Ge
    "H": "\u041D",  # Cyrillic Н
    "I": "\u0399",  # Greek Iota
    "J": "\u0408",  # Cyrillic J
    "K": "\u041A",  # Cyrillic К
    "L": "\u13DE",  # Cherokee letter L
    "M": "\u041C",  # Cyrillic М
    "N": "\u039D",  # Greek Nu
    "O": "\u041E",  # Cyrillic О
    "P": "\u0420",  # Cyrillic Р
    "Q": "\u051A",  # Cyrillic Q-like
    "R": "\u042F",  # Cyrillic Ya
    "S": "\u0405",  # Cyrillic S
    "T": "\u0422",  # Cyrillic Т
    "U": "\u054D",  # Armenian U
    "V": "\u0474",  # Cyrillic Izhitsa
    "W": "\u051C",  # Cyrillic W-like
    "X": "\u0425",  # Cyrillic Х
    "Y": "\u03A5",  # Greek Upsilon
    "Z": "\u13C3",  # Cherokee letter Z
    "0": "\U0001D7F6",  # Mathematical monospace 0
    "1": "\U0001D7F7",  # Mathematical monospace 1
    "2": "\U0001D7F8",  # Mathematical monospace 2
    "3": "\U0001D7F9",  # Mathematical monospace 3
    "4": "\U0001D7FA",  # Mathematical monospace 4
    "5": "\U0001D7FB",  # Mathematical monospace 5
    "6": "\U0001D7FC",  # Mathematical monospace 6
    "7": "\U0001D7FD",  # Mathematical monospace 7
    "8": "\U0001D7FE",  # Mathematical monospace 8
    "9": "\U0001D7FF",  # Mathematical monospace 9
}

# Reverse map for detection
REVERSE_HOMOGLYPH: dict[str, str] = {v: k for k, v in HOMOGLYPH_MAP.items()}


def to_homoglyphs(text: str) -> str:
    """Convert standard ASCII text to visually similar Unicode homoglyphs."""
    return "".join(HOMOGLYPH_MAP.get(c, c) for c in text)


def from_homoglyphs(text: str) -> str:
    """Normalize homoglyph text back to standard ASCII."""
    return "".join(REVERSE_HOMOGLYPH.get(c, c) for c in text)


def detect_homoglyphs(text: str) -> list[dict]:
    """Detect homoglyph characters in text, returning positions and originals."""
    findings = []
    for i, char in enumerate(text):
        if char in REVERSE_HOMOGLYPH:
            findings.append({
                "position": i,
                "homoglyph": char,
                "original": REVERSE_HOMOGLYPH[char],
                "codepoint": f"U+{ord(char):04X}",
            })
    return findings


def has_homoglyphs(text: str) -> bool:
    """Check if text contains any homoglyph characters."""
    return any(c in REVERSE_HOMOGLYPH for c in text)
