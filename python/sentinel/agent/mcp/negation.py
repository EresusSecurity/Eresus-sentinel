"""Negation guard — suppresses capability matches inside denial windows.

Detects whether every occurrence of a keyword in a haystack sits within
a preceding denial clause ("does NOT read_file", "no filesystem access",
"without exec", "refuses to shell"). Returns True only when *every*
occurrence is negated; a single unnegated hit short-circuits to False.
"""

from __future__ import annotations

import re

NEGATION_PATTERN = re.compile(
    r"(?:\b(?:does|do|will|shall|can|may|must|should|could|would)\s+not\b"
    r"|\bnot\s+to\b"
    r"|\b(?:cannot|never|no|without|refus\w*|forbid\w*|disallow\w*"
    r"|prohibit\w*|block\w*|deny|denied|denies)\b)"
    r"[^.\n]{0,60}?\b"
)

_WINDOW_CHARS = 80


def is_all_occurrences_negated(haystack: str, keyword: str) -> bool:
    """Return True iff every occurrence of *keyword* in *haystack* lies
    within a negation window (the previous ``_WINDOW_CHARS``).

    If *keyword* does not appear at all, returns False — callers should
    check membership before invoking this guard.
    """
    kw = keyword.lower()
    # Word-boundary search keeps positions consistent with capability matcher
    _pat = re.compile(r"\b" + re.escape(kw) + r"\b")
    positions = [m.start() for m in _pat.finditer(haystack)]
    if not positions:
        return False

    for pos in positions:
        window = haystack[max(0, pos - _WINDOW_CHARS):pos]
        if not NEGATION_PATTERN.search(window):
            return False
    return True
