"""Top-level normalization helpers.

Applies NFKC, strips invisibles, folds confusables, and composes the
expanded-matching string that pattern scanners should run against.

Extended in this revision to call ``recursive_decode`` so that
multi-layer obfuscation (double URL-encoding, HTML-in-base64, etc.)
is unwrapped before rule matching.
"""

from __future__ import annotations

import unicodedata

from .confusables import fold_confusables
from .decoders import decode_common, recursive_decode
from .invisible import strip_invisible


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


def expand_for_matching(text: str, decode_budget: int = 4) -> str:
    """Return *text* joined with its normalized form and any decoded
    candidates, newline-separated. Run a single regex / substring pass
    over this string instead of invoking the scanner multiple times.

    Parameters
    ----------
    text:
        Raw input text (prompt, tool output, etc.).
    decode_budget:
        Number of recursive decode passes to apply (default 4).
        Each pass applies NFKC → HTML entity → URL → unicode-escape.
        Pass ``budget=1`` for a single normalisation pass with no
        recursive unwrapping.
    """
    normalized = normalize(text)
    # Recursive decode: unwraps double-encoded / homoglyph-obfuscated payloads
    fully_decoded = recursive_decode(normalized, budget=decode_budget)

    parts: list[str] = [text, normalized]
    if fully_decoded not in (text, normalized):
        parts.append(fully_decoded)
    # Additional single-pass decode candidates (base64, hex, rot13)
    parts.extend(decode_common(fully_decoded))
    return "\n".join(parts)

