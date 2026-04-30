"""Base scanner protocol for AIBOM detectors."""
from __future__ import annotations

from abc import ABC, abstractmethod
from pathlib import Path

from sentinel.aibom.models import AIComponent


class BaseAIBOMScanner(ABC):
    name: str = "base"

    @abstractmethod
    def scan(self, root: Path) -> list[AIComponent]:
        ...

    # ---- helpers shared across scanners ------------------------------
    @staticmethod
    def _iter_files(root: Path, suffixes: tuple[str, ...] | None = None, names: tuple[str, ...] | None = None):
        if root.is_file():
            yield root
            return
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            if suffixes and p.suffix.lower() in suffixes:
                yield p
            elif names and p.name in names:
                yield p
            elif not suffixes and not names:
                yield p

    @staticmethod
    def _read(path: Path, limit: int = 200_000) -> str:
        try:
            return path.read_text(encoding="utf-8", errors="replace")[:limit]
        except Exception:
            return ""
