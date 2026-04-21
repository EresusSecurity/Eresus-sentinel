"""Top-level normalization helpers.

Applies NFKC, strips invisibles, folds confusables, and composes the
expanded-matching string that pattern scanners should run against.
"""

from __future__ import annotations

import unicodedata

from .invisible import strip_invisible
from .confusables import fold_confusables
from .decoders import decode_common


def normalize(text: str) -> str:
    """Return the canonical form of *text* for detection-time matching.

    Pipeline:
        1. Unicode NFKC normalization
        2. Invisible / format-character removal
        3. Cyrillic / Greek confusable folding

    Idempotent and deterministic. Empty input is returned unchanged.
    """
    if not text:
        return text
    text = unicodedata.normalize("NFKC", text)
    text = strip_invisible(text)
    text = fold_confusables(text)
    return text


def expand_for_matching(text: str) -> str:
    """Return *text* joined with its normalized form and any decoded
    candidates, newline-separated. Run a single regex / substring pass
    over this string instead of invoking the scanner multiple times.
    """
    parts: list[str] = [text, normalize(text)]
    parts.extend(decode_common(text))
    return "\n".join(parts)
