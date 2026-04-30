"""Thin async wrapper around the synchronous FirewallPipeline."""
from __future__ import annotations

from sentinel.firewall.base import FirewallPipeline, ScanResult
from sentinel.firewall.executor import run_in_pool


class AsyncFirewallPipeline:
    """
    Drop-in async wrapper — delegates all scanning to a sync FirewallPipeline
    running in the shared thread pool so the event loop stays unblocked.
    """

    def __init__(self, sync_pipeline: FirewallPipeline) -> None:
        self._pipe = sync_pipeline

    async def scan(self, text: str, prompt: str = "") -> ScanResult:
        return await run_in_pool(self._pipe.scan, text, prompt)

    # Expose the underlying pipeline for introspection (e.g. /api/scanners)
    @property
    def _scanners(self):
        return getattr(self._pipe, "_scanners", [])

    @property
    def scanner_count(self) -> int:
        if hasattr(self._pipe, "scanner_count"):
            return int(self._pipe.scanner_count)
        return len(self._scanners)

    def add_scanner(self, scanner) -> None:
        self._pipe.add_scanner(scanner)
