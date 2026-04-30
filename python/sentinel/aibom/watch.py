"""File watcher for incremental AIBOM rescans."""
from __future__ import annotations

import logging
import time
from dataclasses import dataclass, field
from pathlib import Path

logger = logging.getLogger(__name__)


@dataclass
class FileChange:
    path: Path
    event: str  # "created", "modified", "deleted"
    timestamp: float = field(default_factory=time.time)


class WatchState:
    """Tracks file modification times for change detection."""

    def __init__(self) -> None:
        self._mtimes: dict[str, float] = {}

    def snapshot(self, root: Path, suffixes: tuple[str, ...] | None = None) -> None:
        for p in root.rglob("*"):
            if not p.is_file():
                continue
            if suffixes and p.suffix.lower() not in suffixes:
                continue
            try:
                self._mtimes[str(p)] = p.stat().st_mtime
            except OSError:
                pass

    def detect_changes(self, root: Path, suffixes: tuple[str, ...] | None = None) -> list[FileChange]:
        changes: list[FileChange] = []
        current: dict[str, float] = {}

        for p in root.rglob("*"):
            if not p.is_file():
                continue
            if suffixes and p.suffix.lower() not in suffixes:
                continue
            try:
                mtime = p.stat().st_mtime
            except OSError:
                continue
            current[str(p)] = mtime
            key = str(p)
            if key not in self._mtimes:
                changes.append(FileChange(path=p, event="created"))
            elif mtime != self._mtimes[key]:
                changes.append(FileChange(path=p, event="modified"))

        for key in self._mtimes:
            if key not in current:
                changes.append(FileChange(path=Path(key), event="deleted"))

        self._mtimes = current
        return changes

    @property
    def file_count(self) -> int:
        return len(self._mtimes)

    def clear(self) -> None:
        self._mtimes.clear()
