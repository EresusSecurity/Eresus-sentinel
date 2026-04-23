"""
Encoding Strategies for Red Team Attacks.

Implements multiple encoding bypass strategies ported from promptfoo:
- Base64
- ROT13
- Hex encoding
- Leetspeak
- Math prompt obfuscation
"""
from __future__ import annotations

import base64
import codecs


def to_base64(text: str) -> str:
    """Encode text to Base64."""
    return base64.b64encode(text.encode()).decode()


def from_base64(text: str) -> str:
    """Decode Base64 text."""
    return base64.b64decode(text.encode()).decode()


def to_rot13(text: str) -> str:
    """Encode text using ROT13."""
    return codecs.encode(text, "rot_13")


def from_rot13(text: str) -> str:
    """Decode ROT13 text."""
    return codecs.decode(text, "rot_13")


def to_hex(text: str) -> str:
    """Encode text as hex."""
    return text.encode().hex()


def from_hex(text: str) -> str:
    """Decode hex text."""
    return bytes.fromhex(text).decode()


LEET_MAP = {
    "a": "4", "e": "3", "i": "1", "o": "0",
    "s": "5", "t": "7", "l": "1", "g": "9",
    "A": "4", "E": "3", "I": "1", "O": "0",
    "S": "5", "T": "7", "L": "1", "G": "9",
}

REVERSE_LEET = {v: k for k, v in LEET_MAP.items()}


def to_leetspeak(text: str) -> str:
    """Encode text as leetspeak."""
    return "".join(LEET_MAP.get(c, c) for c in text)


def to_math_encoding(text: str) -> str:
    """Encode text using mathematical Unicode characters."""
    result = []
    for c in text:
        if c.isalpha():
            if c.isupper():
                # Mathematical bold uppercase: U+1D400 - U+1D419
                result.append(chr(0x1D400 + ord(c) - ord("A")))
            else:
                # Mathematical bold lowercase: U+1D41A - U+1D433
                result.append(chr(0x1D41A + ord(c) - ord("a")))
        else:
            result.append(c)
    return "".join(result)


ENCODING_STRATEGIES = {
    "base64": {"encode": to_base64, "decode": from_base64},
    "rot13": {"encode": to_rot13, "decode": from_rot13},
    "hex": {"encode": to_hex, "decode": from_hex},
    "leetspeak": {"encode": to_leetspeak, "decode": None},
    "math": {"encode": to_math_encoding, "decode": None},
}


def apply_encoding(text: str, strategy: str) -> str:
    """Apply an encoding strategy to text."""
    if strategy not in ENCODING_STRATEGIES:
        raise ValueError(f"Unknown strategy: {strategy}. Available: {list(ENCODING_STRATEGIES)}")
    return ENCODING_STRATEGIES[strategy]["encode"](text)
