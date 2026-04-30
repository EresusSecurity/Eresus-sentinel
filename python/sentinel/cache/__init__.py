"""
Eresus Sentinel — Scan Results Cache.

Provides content-hash-based caching to avoid re-scanning unchanged files,
batch operations with dedup, and TTL-based eviction.
"""

from sentinel.cache.cache_manager import CacheManager
from sentinel.cache.scan_results_cache import ScanResultsCache

__all__ = ["CacheManager", "ScanResultsCache"]
