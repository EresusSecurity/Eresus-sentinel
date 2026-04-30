"""Optional tree-sitter backed parser for multi-language support.

Tree-sitter is an optional dependency. If unavailable, parsing returns a
``ParsedUnit`` with an error message rather than raising, so callers can
gracefully degrade to the Python ``ast`` parser.
"""
from __future__ import annotations

from typing import Optional

from sentinel.sast.static_analysis.parser.base import BaseParser, ParsedUnit

try:  # pragma: no cover - optional dep
    import tree_sitter  # type: ignore
    _TS_AVAILABLE = True
except Exception:  # pragma: no cover
    tree_sitter = None  # type: ignore
    _TS_AVAILABLE = False


class TreeSitterParser(BaseParser):
    """Tree-sitter parser stub.

    Installing ``tree-sitter`` plus a language grammar (e.g.
    ``tree-sitter-python``) enables full parsing. Without those, this parser
    reports a single error so the pipeline can fall back to ast.
    """

    def __init__(self, language: str = "python", grammar: object | None = None) -> None:
        self.language = language
        self._grammar = grammar
        self._parser = None
        if _TS_AVAILABLE and grammar is not None:
            self._parser = tree_sitter.Parser()  # type: ignore[attr-defined]
            try:
                self._parser.set_language(grammar)
            except Exception:
                self._parser = None

    @staticmethod
    def available() -> bool:
        return _TS_AVAILABLE

    def parse_source(self, source: str, path: Optional[str] = None) -> ParsedUnit:
        if not _TS_AVAILABLE or self._parser is None:
            return ParsedUnit(
                path=path,
                language=self.language,
                tree=None,
                source=source,
                errors=["tree-sitter not installed or grammar missing"],
            )
        tree = self._parser.parse(source.encode("utf-8"))  # pragma: no cover
        return ParsedUnit(path=path, language=self.language, tree=tree, source=source)
