"""
Central cache orchestrator — in-memory LRU with optional disk persistence.

Thread-safe via a simple lock.  Entries are evicted when:
  - max_entries is exceeded (LRU order)
  - TTL expires (lazy eviction on access + periodic sweep)
"""

from __future__ import annotations

import hashlib
import json
import logging
import threading
import time
from collections import OrderedDict
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

_log = logging.getLogger("sentinel.cache")


@dataclass
class CacheEntry:
    key: str
    value: Any
    created_at: float = field(default_factory=time.time)
    ttl: float = 3600.0  # seconds

    @property
    def expired(self) -> bool:
        return (time.time() - self.created_at) > self.ttl


class CacheManager:
    """In-memory LRU cache with optional JSON disk persistence."""

    def __init__(
        self,
        max_entries: int = 10_000,
        default_ttl: float = 3600.0,
        persist_path: Optional[str] = None,
    ):
        self._max = max_entries
        self._ttl = default_ttl
        self._store: OrderedDict[str, CacheEntry] = OrderedDict()
        self._lock = threading.Lock()
        self._persist_path = Path(persist_path) if persist_path else None
        self._hits = 0
        self._misses = 0

        if self._persist_path and self._persist_path.exists():
            self._load_from_disk()

    def get(self, key: str) -> Optional[Any]:
        """Get a cached value. Returns None on miss or expiry."""
        with self._lock:
            entry = self._store.get(key)
            if entry is None:
                self._misses += 1
                return None
            if entry.expired:
                del self._store[key]
                self._misses += 1
                return None
            self._store.move_to_end(key)
            self._hits += 1
            return entry.value

    def put(self, key: str, value: Any, ttl: Optional[float] = None) -> None:
        """Store a value. Evicts oldest entries if capacity exceeded."""
        with self._lock:
            if key in self._store:
                del self._store[key]
            self._store[key] = CacheEntry(
                key=key, value=value, ttl=ttl or self._ttl
            )
            self._store.move_to_end(key)
            while len(self._store) > self._max:
                self._store.popitem(last=False)

    def invalidate(self, key: str) -> bool:
        """Remove a specific key. Returns True if it existed."""
        with self._lock:
            if key in self._store:
                del self._store[key]
                return True
            return False

    def clear(self) -> int:
        """Remove all entries. Returns count removed."""
        with self._lock:
            count = len(self._store)
            self._store.clear()
            return count

    def sweep_expired(self) -> int:
        """Remove all expired entries. Returns count removed."""
        with self._lock:
            expired_keys = [k for k, v in self._store.items() if v.expired]
            for k in expired_keys:
                del self._store[k]
            return len(expired_keys)

    @property
    def size(self) -> int:
        return len(self._store)

    @property
    def stats(self) -> dict:
        return {
            "size": len(self._store),
            "max_entries": self._max,
            "hits": self._hits,
            "misses": self._misses,
            "hit_rate": self._hits / max(1, self._hits + self._misses),
        }

    def persist(self) -> None:
        """Write cache to disk as JSON (values must be JSON-serializable)."""
        if not self._persist_path:
            return
        with self._lock:
            data = {}
            for key, entry in self._store.items():
                if not entry.expired:
                    try:
                        data[key] = {
                            "value": entry.value,
                            "created_at": entry.created_at,
                            "ttl": entry.ttl,
                        }
                    except (TypeError, ValueError):
                        pass  # Skip non-serializable entries
            self._persist_path.parent.mkdir(parents=True, exist_ok=True)
            self._persist_path.write_text(json.dumps(data))
            _log.debug("Persisted %d cache entries to %s", len(data), self._persist_path)

    def _load_from_disk(self) -> None:
        try:
            data = json.loads(self._persist_path.read_text())  # type: ignore[union-attr]
            now = time.time()
            for key, entry_data in data.items():
                created = entry_data.get("created_at", now)
                ttl = entry_data.get("ttl", self._ttl)
                if (now - created) < ttl:
                    self._store[key] = CacheEntry(
                        key=key,
                        value=entry_data["value"],
                        created_at=created,
                        ttl=ttl,
                    )
            _log.debug("Loaded %d cache entries from disk", len(self._store))
        except Exception as exc:
            _log.warning("Failed to load cache from disk: %s", exc)


def content_hash(data: bytes) -> str:
    """SHA-256 content hash for cache keys."""
    return hashlib.sha256(data).hexdigest()


def file_cache_key(filepath: str) -> str:
    """Cache key combining path + mtime + size for change detection."""
    p = Path(filepath)
    try:
        stat = p.stat()
        return f"{filepath}:{stat.st_size}:{stat.st_mtime_ns}"
    except OSError:
        return filepath
