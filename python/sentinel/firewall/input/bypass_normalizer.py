"""
Eresus Sentinel — Bypass Normalizer.

Normalizes adversarial text mutations before pattern matching, including:
  - Leet speak  (4→a, 3→e, 1/!→i, 0→o, 5/$→s, 7→t, @→a)
  - Unicode homoglyphs  (Cyrillic/Greek lookalikes → Latin)
  - Zero-width characters  (U+200B, U+200C, U+200D, U+FEFF, etc.)
  - Punctuation insertion  (f.u.c.k, f-u-c-k, f_u_c_k)
  - Repeated characters  (fuuuuck → fuck)
  - Case normalization (always lowercased before matching)
  - HTML entity decoding (&lt; → <, &#102; → f, &#x66; → f)
  - URL percent-decode (%66%75%63%6B → fuck)
  - Unicode NFKC normalization (ﬁ → fi, ™ → TM)

Also provides a ``BypassDetector`` that flags inputs where bypass techniques
are actively being used, regardless of the final normalized content.
"""

from __future__ import annotations

import html
import re
import unicodedata
import urllib.parse
from typing import NamedTuple

# ─── Homoglyph map ────────────────────────────────────────────────────────────
# Maps confusable Unicode codepoints → ASCII equivalent
# Sources: Unicode confusables.txt, Homoglyph Attack toolkit
_HOMOGLYPH_MAP: dict[str, str] = {
    # Cyrillic → Latin
    "\u0430": "a",  # а → a
    "\u0435": "e",  # е → e
    "\u0456": "i",  # і → i
    "\u043e": "o",  # о → o
    "\u0440": "r",  # р → r
    "\u0441": "c",  # с → c
    "\u0445": "x",  # х → x
    "\u0443": "y",  # у → y
    "\u0432": "b",  # в → b (near-lookalike in some fonts)
    "\u0412": "B",  # В
    "\u0410": "A",  # А
    "\u0415": "E",  # Е
    "\u041e": "O",  # О
    "\u0420": "R",  # Р
    "\u0421": "C",  # С
    "\u0422": "T",  # Т
    "\u0425": "X",  # Х
    "\u0419": "U",  # Й  (rough lookalike)
    "\u041a": "K",  # К
    "\u041c": "M",  # М
    "\u041d": "H",  # Н
    "\u0446": "u",  # ц (contextual)
    # Greek → Latin
    "\u03b1": "a",  # α
    "\u03b2": "b",  # β
    "\u03b5": "e",  # ε
    "\u03b9": "i",  # ι
    "\u03bf": "o",  # ο
    "\u03c1": "r",  # ρ
    "\u03c3": "s",  # σ
    "\u03c4": "t",  # τ
    "\u03c5": "u",  # υ
    "\u03bd": "v",  # ν
    "\u03c7": "x",  # χ
    "\u0391": "A",  # Α
    "\u0392": "B",  # Β
    "\u0395": "E",  # Ε
    "\u0396": "Z",  # Ζ
    "\u0397": "H",  # Η
    "\u0399": "I",  # Ι
    "\u039a": "K",  # Κ
    "\u039c": "M",  # Μ
    "\u039d": "N",  # Ν
    "\u039f": "O",  # Ο
    "\u03a1": "P",  # Ρ
    "\u03a4": "T",  # Τ
    "\u03a5": "Y",  # Υ
    "\u03a7": "X",  # Χ
    # Mathematical bold/italic/fraktur variants
    "\U0001d41a": "a", "\U0001d41b": "b", "\U0001d41c": "c",
    "\U0001d41d": "d", "\U0001d41e": "e", "\U0001d41f": "f",
    "\U0001d420": "g", "\U0001d421": "h", "\U0001d422": "i",
    "\U0001d423": "j", "\U0001d424": "k", "\U0001d425": "l",
    "\U0001d426": "m", "\U0001d427": "n", "\U0001d428": "o",
    "\U0001d429": "p", "\U0001d42a": "q", "\U0001d42b": "r",
    "\U0001d42c": "s", "\U0001d42d": "t", "\U0001d42e": "u",
    "\U0001d42f": "v", "\U0001d430": "w", "\U0001d431": "x",
    "\U0001d432": "y", "\U0001d433": "z",
    # Fullwidth Latin
    "\uff41": "a", "\uff42": "b", "\uff43": "c", "\uff44": "d",
    "\uff45": "e", "\uff46": "f", "\uff47": "g", "\uff48": "h",
    "\uff49": "i", "\uff4a": "j", "\uff4b": "k", "\uff4c": "l",
    "\uff4d": "m", "\uff4e": "n", "\uff4f": "o", "\uff50": "p",
    "\uff51": "q", "\uff52": "r", "\uff53": "s", "\uff54": "t",
    "\uff55": "u", "\uff56": "v", "\uff57": "w", "\uff58": "x",
    "\uff59": "y", "\uff5a": "z",
    "\uff21": "A", "\uff22": "B", "\uff23": "C", "\uff24": "D",
    "\uff25": "E", "\uff26": "F", "\uff27": "G", "\uff28": "H",
    "\uff29": "I", "\uff2a": "J", "\uff2b": "K", "\uff2c": "L",
    "\uff2d": "M", "\uff2e": "N", "\uff2f": "O", "\uff30": "P",
    "\uff31": "Q", "\uff32": "R", "\uff33": "S", "\uff34": "T",
    "\uff35": "U", "\uff36": "V", "\uff37": "W", "\uff38": "X",
    "\uff39": "Y", "\uff3a": "Z",
    # Superscript digits
    "\u00b2": "2", "\u00b3": "3", "\u00b9": "1",
    "\u2070": "0", "\u2074": "4", "\u2075": "5",
    "\u2076": "6", "\u2077": "7", "\u2078": "8", "\u2079": "9",
}

# ─── Zero-width / invisible character set ─────────────────────────────────────
_ZERO_WIDTH_CHARS = frozenset({
    "\u200b",  # ZERO WIDTH SPACE
    "\u200c",  # ZERO WIDTH NON-JOINER
    "\u200d",  # ZERO WIDTH JOINER
    "\u2060",  # WORD JOINER
    "\ufeff",  # BYTE ORDER MARK / ZERO WIDTH NO-BREAK SPACE
    "\u00ad",  # SOFT HYPHEN
    "\u034f",  # COMBINING GRAPHEME JOINER
    "\u115f",  # HANGUL CHOSEONG FILLER
    "\u1160",  # HANGUL JUNGSEONG FILLER
    "\u17b4",  # KHMER VOWEL INHERENT AQ
    "\u17b5",  # KHMER VOWEL INHERENT AA
    "\u3164",  # HANGUL FILLER
    "\ufe00",  "\ufe01",  "\ufe02",  "\ufe03",
    "\ufe04",  "\ufe05",  "\ufe06",  "\ufe07",
    "\ufe08",  "\ufe09",  "\ufe0a",  "\ufe0b",
    "\ufe0c",  "\ufe0d",  "\ufe0e",  "\ufe0f",  # Variation selectors
})

# ─── Leet speak → ASCII ───────────────────────────────────────────────────────
_LEET_MAP: dict[str, str] = {
    "4":  "a",
    "@":  "a",
    "8":  "b",
    "(":  "c",
    "3":  "e",
    "9":  "g",
    "#":  "h",
    "!":  "i",
    "1":  "i",
    "|":  "i",
    "0":  "o",
    "5":  "s",
    "$":  "s",
    "7":  "t",
    "+":  "t",
    "2":  "z",
    "6":  "b",  # contextual
}

# ─── Separator insertion pattern ──────────────────────────────────────────────
# Matches single separator chars inserted between each letter: f.u.c.k, f-u-c-k
_SEPARATOR_RE = re.compile(r"(?<=[a-z0-9])[\.\-_\s\*\\\/](?=[a-z0-9])", re.IGNORECASE)

# ─── Repeated character reduction ─────────────────────────────────────────────
# fuuuuck → fuck  (reduce >2 same consecutive chars to 1)
_REPEAT_RE = re.compile(r"(.)\1{2,}")

# ─── HTML entity pattern ──────────────────────────────────────────────────────
_HTML_ENTITY_RE = re.compile(r"&(?:#\d+|#x[0-9a-fA-F]+|[a-zA-Z]+);")

# ─── URL percent-encode ───────────────────────────────────────────────────────
_PCT_ENCODE_RE = re.compile(r"%[0-9a-fA-F]{2}")


class BypassSignals(NamedTuple):
    """Signals detected during normalization."""
    zero_width_chars: bool
    homoglyphs: bool
    leet_speak: bool
    separator_insertion: bool
    repeated_chars: bool
    html_entities: bool
    url_encoding: bool
    spaced_letters: bool

    @property
    def any_bypass(self) -> bool:
        return any(self)

    @property
    def score(self) -> float:
        """0.0–1.0 — how aggressively bypass was attempted."""
        signals = [
            self.zero_width_chars * 0.9,
            self.homoglyphs * 0.7,
            self.leet_speak * 0.5,
            self.separator_insertion * 0.4,
            self.repeated_chars * 0.2,
            self.html_entities * 0.6,
            self.url_encoding * 0.6,
            self.spaced_letters * 0.5,
        ]
        return min(1.0, sum(s for s in signals if s > 0))


class BypassNormalizer:
    """
    Text normalization pipeline for bypass detection.

    Produces a normalized (de-obfuscated) version of text and detects
    which bypass techniques were used.

    Usage::

        normalizer = BypassNormalizer()
        normalized, signals = normalizer.normalize(text)
        if signals.any_bypass:
            # raise alert with signals.score as confidence boost
    """

    def normalize_words(self, text: str) -> tuple[str, BypassSignals]:
        """Normalize each whitespace-separated token individually then rejoin.

        Prevents the separator-stripping pass from merging adjacent words
        (e.g. "heroin kaufen" → "heroinkaufen"). Use this when the input
        contains natural-language sentences and you need lexicon word-matching.
        """
        tokens = text.split()
        if not tokens:
            return text, BypassSignals(*([False] * 8))
        parts: list[str] = []
        merged_signals: list[BypassSignals] = []
        for token in tokens:
            norm_token, sig = self.normalize(token)
            parts.append(norm_token)
            merged_signals.append(sig)
        combined = " ".join(parts)
        # OR all signal fields across tokens
        any_zw  = any(s.zero_width_chars for s in merged_signals)
        any_hg  = any(s.homoglyphs for s in merged_signals)
        any_lt  = any(s.leet_speak for s in merged_signals)
        any_sep = any(s.separator_insertion for s in merged_signals)
        any_rep = any(s.repeated_chars for s in merged_signals)
        any_htm = any(s.html_entities for s in merged_signals)
        any_url = any(s.url_encoding for s in merged_signals)
        any_sp  = any(s.spaced_letters for s in merged_signals)
        final_sig = BypassSignals(any_zw, any_hg, any_lt, any_sep,
                                   any_rep, any_htm, any_url, any_sp)
        return combined, final_sig

    def normalize(self, text: str) -> tuple[str, BypassSignals]:
        """
        Normalize text and return (normalized_text, BypassSignals).

        The normalized text is suitable for word-level matching with toxic
        lexicon entries. Signals indicate which bypass techniques were found.
        """

        # Step 1: NFKC unicode normalization (collapses ligatures, fullwidth, etc.)
        text = unicodedata.normalize("NFKC", text)

        # Step 2: Detect + strip zero-width chars
        zw = any(c in _ZERO_WIDTH_CHARS for c in text)
        text = "".join(c for c in text if c not in _ZERO_WIDTH_CHARS)

        # Step 3: HTML entity decode
        html_ent = bool(_HTML_ENTITY_RE.search(text))
        if html_ent:
            text = html.unescape(text)

        # Step 4: URL percent-decode
        url_enc = bool(_PCT_ENCODE_RE.search(text))
        if url_enc:
            try:
                decoded = urllib.parse.unquote(text, errors="replace")
                if decoded != text:
                    text = decoded
                else:
                    url_enc = False
            except Exception:
                url_enc = False

        # Step 5: Homoglyph substitution
        hg_replaced = False
        out = []
        for ch in text:
            replacement = _HOMOGLYPH_MAP.get(ch)
            if replacement is not None:
                out.append(replacement)
                hg_replaced = True
            else:
                out.append(ch)
        text = "".join(out)

        # Step 6: Detect spaced letters (f u c k pattern) before stripping separators
        spaced = bool(re.search(
            r"\b[a-z]\s[a-z]\s[a-z](?:\s[a-z])*\b", text, re.IGNORECASE
        ))

        # Step 7: Separator removal (f.u.c.k → fuck)
        sep_found = bool(_SEPARATOR_RE.search(text))
        if sep_found:
            text = _SEPARATOR_RE.sub("", text)

        # Step 8: Leet speak normalization (only in ASCII range to avoid false-positives)
        leet_found = False
        leet_out = []
        for ch in text:
            repl = _LEET_MAP.get(ch)
            if repl is not None and ch not in ".,!?":  # preserve punctuation outside leet
                # Only flag as leet if the char is actually in leet positions
                leet_out.append(repl)
                leet_found = True
            else:
                leet_out.append(ch)
        leet_text = "".join(leet_out)

        # Step 9: Repeated char reduction (fuuuck → fuck)
        rep_found = bool(_REPEAT_RE.search(text))
        text = _REPEAT_RE.sub(r"\1\1", text)  # keep 2 max so double-letters still work
        leet_text = _REPEAT_RE.sub(r"\1\1", leet_text)

        # Step 10: Lowercase for matching
        normalized = text.lower()
        leet_normalized = leet_text.lower()

        # Merge: if leet produced more change, prefer it
        final = leet_normalized if leet_found else normalized

        signals = BypassSignals(
            zero_width_chars=zw,
            homoglyphs=hg_replaced,
            leet_speak=leet_found,
            separator_insertion=sep_found,
            repeated_chars=rep_found,
            html_entities=html_ent,
            url_encoding=url_enc,
            spaced_letters=spaced,
        )
        return final, signals

    def normalize_both(self, text: str) -> tuple[str, str, BypassSignals]:
        """Return (original_lower, normalized, signals) — useful for dual matching."""
        normalized, signals = self.normalize(text)
        return text.lower(), normalized, signals
