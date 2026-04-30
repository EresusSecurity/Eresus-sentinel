"""Scan result cache. blake2b(path+size+mtime) keyed JSON store."""

from __future__ import annotations

import hashlib
import json
import logging
import os
import time
from pathlib import Path
from typing import Any, Optional

log = logging.getLogger(__name__)


def _fingerprint(filepath: str) -> Optional[str]:
    """blake2b hash of path+size+mtime. None if file missing."""
    try:
        st = os.stat(filepath)
        raw = f"{os.path.abspath(filepath)}:{st.st_size}:{st.st_mtime}"
        return hashlib.blake2b(raw.encode(), digest_size=16).hexdigest()
    except OSError:
        return None


class ScanCache:
    """File-based scan cache with TTL eviction."""

    def __init__(self, cache_dir: str = ".sentinel-cache", ttl: int = 86400, enabled: bool = True):
        self._dir = Path(cache_dir)
        self._ttl = ttl
        self._enabled = enabled
        self.hits = 0
        self.misses = 0
        if enabled:
            self._dir.mkdir(parents=True, exist_ok=True)

    def get(self, filepath: str) -> Optional[list[dict[str, Any]]]:
        if not self._enabled:
            self.misses += 1
            return None
        key = _fingerprint(filepath)
        if not key:
            self.misses += 1
            return None
        cf = self._dir / f"{key}.json"
        if not cf.exists():
            self.misses += 1
            return None
        try:
            data = json.loads(cf.read_text())
            if time.time() - data.get("t", 0) > self._ttl:
                cf.unlink(missing_ok=True)
                self.misses += 1
                return None
            self.hits += 1
            return data.get("f", [])
        except (json.JSONDecodeError, OSError):
            self.misses += 1
            return None

    def put(self, filepath: str, findings: list[dict[str, Any]]) -> None:
        if not self._enabled:
            return
        key = _fingerprint(filepath)
        if not key:
            return
        try:
            (self._dir / f"{key}.json").write_text(
                json.dumps({"t": time.time(), "f": findings}, default=str)
            )
        except OSError as e:
            log.warning("cache write failed: %s: %s", filepath, e)

    def clear(self) -> int:
        n = 0
        for f in self._dir.glob("*.json"):
            f.unlink(missing_ok=True)
            n += 1
        self.hits = self.misses = 0
        return n
