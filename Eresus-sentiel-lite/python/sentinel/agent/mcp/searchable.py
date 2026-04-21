"""Searchable-text helpers used by capability and auth analyzers.

Flattens an MCP tool definition to a single lower-case string and
concatenates the Unicode-normalized form so homoglyph / invisible
bypasses fail at match time.
"""

from __future__ import annotations

import json
from typing import Any

from ...normalize import normalize as _normalize


def build_searchable(tool: dict[str, Any]) -> str:
    """Return the raw + normalized flattened JSON blob for matching.

    Both variants are newline-joined so a single substring scan covers
    attackers who obfuscate via homoglyphs and attackers who don't.
    """
    raw = json.dumps(tool, ensure_ascii=False).lower()
    return raw + "\n" + _normalize(raw).lower()
