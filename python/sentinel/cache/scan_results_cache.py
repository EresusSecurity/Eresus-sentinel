"""
Scan results cache — wraps CacheManager for artifact/firewall scan results.

Provides file-level caching so unchanged files are not re-scanned.
"""

from __future__ import annotations

import logging
from typing import Optional

from sentinel.cache.cache_manager import CacheManager, file_cache_key
from sentinel.finding import Finding

_log = logging.getLogger("sentinel.cache.scan_results")


class ScanResultsCache:
    """Cache scan results keyed by file path + mtime + size."""

    def __init__(
        self,
        max_entries: int = 50_000,
        ttl: float = 7200.0,
        persist_path: Optional[str] = None,
    ):
        self._cache = CacheManager(
            max_entries=max_entries,
            default_ttl=ttl,
            persist_path=persist_path,
        )

    def get_findings(self, filepath: str) -> Optional[list[dict]]:
        """Return cached findings for a file, or None if not cached / stale."""
        key = file_cache_key(filepath)
        return self._cache.get(key)

    def store_findings(self, filepath: str, findings: list[Finding]) -> None:
        """Cache findings for a file."""
        key = file_cache_key(filepath)
        serialized = []
        for f in findings:
            try:
                serialized.append({
                    "rule_id": getattr(f, "rule_id", ""),
                    "title": getattr(f, "title", ""),
                    "severity": f.severity.value if hasattr(f.severity, "value") else str(f.severity),
                    "confidence": getattr(f, "confidence", 0.0),
                    "description": getattr(f, "description", ""),
                })
            except Exception:
                pass
        self._cache.put(key, serialized)

    def invalidate(self, filepath: str) -> bool:
        """Invalidate cached results for a file."""
        key = file_cache_key(filepath)
        return self._cache.invalidate(key)

    def clear(self) -> int:
        """Clear all cached results."""
        return self._cache.clear()

    def persist(self) -> None:
        """Persist cache to disk."""
        self._cache.persist()

    @property
    def stats(self) -> dict:
        return self._cache.stats

    def batch_check(self, filepaths: list[str]) -> tuple[list[str], list[str]]:
        """Split filepaths into (cached, uncached) lists.

        Returns:
            (cached_paths, uncached_paths) — cached paths already have results,
            uncached paths need scanning.
        """
        cached = []
        uncached = []
        for fp in filepaths:
            if self.get_findings(fp) is not None:
                cached.append(fp)
            else:
                uncached.append(fp)
        return cached, uncached
