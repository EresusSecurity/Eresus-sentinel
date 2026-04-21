"""Persistent corpus management with deduplication and minimization."""

from __future__ import annotations

import hashlib
import json
import logging
import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


@dataclass
class CorpusEntry:
    """A single entry in the persistent corpus."""
    sha256: str
    size: int
    filename: str
    category: str = ""
    tags: list[str] = field(default_factory=list)
    is_interesting: bool = False
    is_crash: bool = False
    coverage_increase: int = 0


class Corpus:
    """Persistent corpus with deduplication, minimization, archival."""

    def __init__(self, root_dir: str | Path):
        self._root = Path(root_dir)
        self._root.mkdir(parents=True, exist_ok=True)
        self._queue_dir = self._root / "queue"
        self._crashes_dir = self._root / "crashes"
        self._interesting_dir = self._root / "interesting"
        self._archive_dir = self._root / "archive"
        self._meta_file = self._root / "corpus_meta.json"

        for d in [self._queue_dir, self._crashes_dir,
                  self._interesting_dir, self._archive_dir]:
            d.mkdir(exist_ok=True)

        self._entries: dict[str, CorpusEntry] = {}
        self._load_meta()

    def _load_meta(self) -> None:
        if self._meta_file.exists():
            data = json.loads(self._meta_file.read_text(encoding="utf-8"))
            for entry_data in data.get("entries", []):
                entry = CorpusEntry(**entry_data)
                self._entries[entry.sha256] = entry

    def _save_meta(self) -> None:
        data = {
            "entries": [
                {
                    "sha256": e.sha256,
                    "size": e.size,
                    "filename": e.filename,
                    "category": e.category,
                    "tags": e.tags,
                    "is_interesting": e.is_interesting,
                    "is_crash": e.is_crash,
                    "coverage_increase": e.coverage_increase,
                }
                for e in self._entries.values()
            ],
            "total": len(self._entries),
        }
        self._meta_file.write_text(
            json.dumps(data, indent=2), encoding="utf-8"
        )

    def add(
        self,
        data: bytes,
        filename: str = "",
        category: str = "",
        tags: list[str] | None = None,
        is_interesting: bool = False,
        is_crash: bool = False,
        coverage_increase: int = 0,
    ) -> Optional[CorpusEntry]:
        sha = hashlib.sha256(data).hexdigest()

        if sha in self._entries:
            return None

        if not filename:
            filename = f"{sha[:16]}.bin"

        entry = CorpusEntry(
            sha256=sha,
            size=len(data),
            filename=filename,
            category=category,
            tags=tags or [],
            is_interesting=is_interesting,
            is_crash=is_crash,
            coverage_increase=coverage_increase,
        )

        if is_crash:
            target_dir = self._crashes_dir
        elif is_interesting:
            target_dir = self._interesting_dir
        else:
            target_dir = self._queue_dir

        (target_dir / filename).write_bytes(data)
        self._entries[sha] = entry
        self._save_meta()

        return entry

    def contains(self, data: bytes) -> bool:
        sha = hashlib.sha256(data).hexdigest()
        return sha in self._entries

    def get_all(self) -> list[CorpusEntry]:
        return list(self._entries.values())

    def get_queue(self) -> list[Path]:
        return sorted(self._queue_dir.glob("*"))

    def get_crashes(self) -> list[Path]:
        return sorted(self._crashes_dir.glob("*"))

    def get_interesting(self) -> list[Path]:
        return sorted(self._interesting_dir.glob("*"))

    def minimize(self, keep_fn: Optional[callable] = None) -> int:
        """Remove entries that don't contribute new coverage.

        If keep_fn is provided, only keep entries where keep_fn(entry) is True.
        Returns the number of entries removed.
        """
        removed = 0
        to_remove = []

        for sha, entry in self._entries.items():
            if keep_fn and not keep_fn(entry):
                to_remove.append(sha)
            elif not entry.is_crash and not entry.is_interesting and entry.coverage_increase == 0:
                to_remove.append(sha)

        for sha in to_remove:
            entry = self._entries.pop(sha)
            for d in [self._queue_dir, self._interesting_dir]:
                p = d / entry.filename
                if p.exists():
                    p.unlink()
            removed += 1

        self._save_meta()
        logger.info("Corpus minimized: removed %d entries", removed)
        return removed

    def archive(self) -> None:
        """Move current corpus to archive."""
        import time
        ts = str(int(time.time()))
        archive_path = self._archive_dir / ts
        archive_path.mkdir(exist_ok=True)

        for d in [self._queue_dir, self._crashes_dir, self._interesting_dir]:
            for f in d.glob("*"):
                shutil.copy2(f, archive_path / f.name)

        logger.info("Corpus archived to %s", archive_path)

    @property
    def size(self) -> int:
        return len(self._entries)

    @property
    def stats(self) -> dict:
        return {
            "total": len(self._entries),
            "queue": len(list(self._queue_dir.glob("*"))),
            "crashes": len(list(self._crashes_dir.glob("*"))),
            "interesting": len(list(self._interesting_dir.glob("*"))),
            "total_bytes": sum(e.size for e in self._entries.values()),
        }
