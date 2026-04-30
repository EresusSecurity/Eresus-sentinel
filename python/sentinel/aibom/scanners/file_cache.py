"""File-based scan cache to avoid re-reading unchanged files."""
from __future__ import annotations

import hashlib
from functools import lru_cache
from pathlib import Path
from typing import NamedTuple


class CacheEntry(NamedTuple):
    path: str
    mtime: float
    size: int
    content_hash: str


class FileCache:
    """Simple file cache that tracks mtimes and content hashes."""

    def __init__(self) -> None:
        self._cache: dict[str, CacheEntry] = {}

    def is_stale(self, path: Path) -> bool:
        key = str(path)
        if key not in self._cache:
            return True
        entry = self._cache[key]
        try:
            stat = path.stat()
            return stat.st_mtime != entry.mtime or stat.st_size != entry.size
        except OSError:
            return True

    def update(self, path: Path, content: str) -> CacheEntry:
        stat = path.stat()
        h = hashlib.sha256(content.encode("utf-8", errors="replace")).hexdigest()[:16]
        entry = CacheEntry(
            path=str(path),
            mtime=stat.st_mtime,
            size=stat.st_size,
            content_hash=h,
        )
        self._cache[str(path)] = entry
        return entry

    def get(self, path: Path) -> CacheEntry | None:
        return self._cache.get(str(path))

    def invalidate(self, path: Path) -> None:
        self._cache.pop(str(path), None)

    def clear(self) -> None:
        self._cache.clear()

    @property
    def size(self) -> int:
        return len(self._cache)


_global_cache = FileCache()


def get_global_cache() -> FileCache:
    return _global_cache


@lru_cache(maxsize=512)
def read_cached(path: str, limit: int = 200_000) -> str:
    """Read file with LRU cache — suitable for single-run scans."""
    try:
        return Path(path).read_text(encoding="utf-8", errors="replace")[:limit]
    except Exception:
        return ""
