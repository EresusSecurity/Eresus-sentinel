"""Python source parser backed by the stdlib ``ast`` module."""
from __future__ import annotations

import ast
from typing import Optional

from sentinel.sast.static_analysis.parser.base import BaseParser, ParsedUnit


class PythonParser(BaseParser):
    language = "python"

    def parse_source(self, source: str, path: Optional[str] = None) -> ParsedUnit:
        errors: list[str] = []
        tree = None
        try:
            tree = ast.parse(source, filename=path or "<string>")
        except SyntaxError as exc:
            errors.append(f"syntax error: {exc.msg} at line {exc.lineno}")
        return ParsedUnit(
            path=path,
            language=self.language,
            tree=tree,
            source=source,
            errors=errors,
        )
