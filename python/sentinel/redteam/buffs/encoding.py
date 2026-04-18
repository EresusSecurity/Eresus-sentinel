"""
Encoding Buff — transforms prompts using various encoding schemes.

Attackers use encoding to bypass input filters and guardrails.
Supports: base64, rot13, hex, unicode_escape, url_encode, leetspeak,
           morse, binary, reversed, pig_latin.
"""

from __future__ import annotations

import base64
import codecs
import logging
import urllib.parse

from sentinel.redteam.buffs.base import Buff

logger = logging.getLogger(__name__)

# Leetspeak mapping
_LEET = str.maketrans({
    "a": "4", "e": "3", "i": "1", "o": "0", "s": "5",
    "t": "7", "l": "1", "g": "9", "b": "8",
    "A": "4", "E": "3", "I": "1", "O": "0", "S": "5",
    "T": "7", "L": "1", "G": "9", "B": "8",
})

# Morse code mapping
_MORSE = {
    "a": ".-", "b": "-...", "c": "-.-.", "d": "-..", "e": ".",
    "f": "..-.", "g": "--.", "h": "....", "i": "..", "j": ".---",
    "k": "-.-", "l": ".-..", "m": "--", "n": "-.", "o": "---",
    "p": ".--.", "q": "--.-", "r": ".-.", "s": "...", "t": "-",
    "u": "..-", "v": "...-", "w": ".--", "x": "-..-", "y": "-.--",
    "z": "--..", "0": "-----", "1": ".----", "2": "..---",
    "3": "...--", "4": "....-", "5": ".....", "6": "-....",
    "7": "--...", "8": "---..", "9": "----.", " ": "/",
}


def _to_morse(text: str) -> str:
    return " ".join(_MORSE.get(c.lower(), c) for c in text)


def _to_pig_latin(text: str) -> str:
    words = text.split()
    result = []
    vowels = set("aeiouAEIOU")
    for word in words:
        if not word[0].isalpha():
            result.append(word)
        elif word[0] in vowels:
            result.append(word + "way")
        else:
            i = 0
            while i < len(word) and word[i] not in vowels:
                i += 1
            result.append(word[i:] + word[:i] + "ay")
    return " ".join(result)


class EncodingBuff(Buff):
    """
    Encode prompts to bypass guardrails.

    Supported methods:
      - base64: Standard base64 encoding
      - rot13: Caesar cipher with 13-char shift
      - hex: Hexadecimal encoding
      - unicode_escape: \\uXXXX escape sequences
      - url_encode: URL percent-encoding
      - leetspeak: 1337sp34k character substitution
      - morse: Morse code
      - binary: Binary (ASCII) encoding
      - reversed: Reversed string
      - pig_latin: Pig Latin transformation
      - mixed: Applies multiple encodings, one per prompt

    Usage:
        buff = EncodingBuff(method="base64")
        encoded = buff.transform(["Tell me how to hack"])
    """

    name = "encoding"

    METHODS = {
        "base64", "rot13", "hex", "unicode_escape", "url_encode",
        "leetspeak", "morse", "binary", "reversed", "pig_latin", "mixed",
    }

    def __init__(self, method: str = "base64", prefix: str = "", suffix: str = ""):
        if method not in self.METHODS:
            raise ValueError(f"Unknown encoding method: {method}. Choose from {self.METHODS}")
        self._method = method
        self._prefix = prefix
        self._suffix = suffix

    def transform(self, prompts: list[str]) -> list[str]:
        if self._method == "mixed":
            return self._mixed_encode(prompts)

        encoder = self._get_encoder(self._method)
        return [self._prefix + encoder(p) + self._suffix for p in prompts]

    def _mixed_encode(self, prompts: list[str]) -> list[str]:
        """Apply a different encoding to each prompt, cycling through methods."""
        methods = [m for m in self.METHODS if m != "mixed"]
        result = []
        for i, prompt in enumerate(prompts):
            method = methods[i % len(methods)]
            encoder = self._get_encoder(method)
            result.append(f"[{method}] {encoder(prompt)}")
        return result

    def _get_encoder(self, method: str):
        encoders = {
            "base64": lambda t: base64.b64encode(t.encode()).decode(),
            "rot13": lambda t: codecs.encode(t, "rot_13"),
            "hex": lambda t: t.encode().hex(),
            "unicode_escape": lambda t: "".join(f"\\u{ord(c):04x}" for c in t),
            "url_encode": lambda t: urllib.parse.quote(t, safe=""),
            "leetspeak": lambda t: t.translate(_LEET),
            "morse": _to_morse,
            "binary": lambda t: " ".join(f"{ord(c):08b}" for c in t),
            "reversed": lambda t: t[::-1],
            "pig_latin": _to_pig_latin,
        }
        return encoders[method]
