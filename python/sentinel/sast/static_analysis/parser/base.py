"""Abstract parser interface."""
from __future__ import annotations

from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional


@dataclass
class ParsedUnit:
    """A parsed source unit (file or snippet)."""
    path: Optional[str]
    language: str
    tree: Any
    source: str
    errors: list[str] = field(default_factory=list)

    @property
    def ok(self) -> bool:
        return not self.errors


class BaseParser(ABC):
    """Every language parser must produce a ParsedUnit."""

    language: str = "unknown"

    @abstractmethod
    def parse_source(self, source: str, path: Optional[str] = None) -> ParsedUnit:
        ...

    def parse_file(self, path: str | Path) -> ParsedUnit:
        p = Path(path)
        src = p.read_text(encoding="utf-8", errors="replace")
        return self.parse_source(src, path=str(p))
