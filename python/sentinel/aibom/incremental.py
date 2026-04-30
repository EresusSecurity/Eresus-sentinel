"""Incremental AIBOM scan — only rescan changed files."""
from __future__ import annotations

import logging
from pathlib import Path

from sentinel.aibom.models import AIBOMResult
from sentinel.aibom.scanners.base import BaseAIBOMScanner
from sentinel.aibom.watch import FileChange, WatchState

logger = logging.getLogger(__name__)


class IncrementalScanner:
    """Run AIBOM scanners only on changed files, merging with previous results."""

    def __init__(self, scanners: list[BaseAIBOMScanner]) -> None:
        self._scanners = scanners
        self._watch = WatchState()
        self._previous: AIBOMResult | None = None

    def initial_scan(self, root: Path) -> AIBOMResult:
        self._watch.snapshot(root)
        result = AIBOMResult()
        for scanner in self._scanners:
            components = scanner.scan(root)
            for comp in components:
                result.add(comp)
        self._previous = result
        logger.info("Initial scan: %d components from %d files",
                     len(result.components), self._watch.file_count)
        return result

    def rescan(self, root: Path) -> tuple[AIBOMResult, list[FileChange]]:
        changes = self._watch.detect_changes(root)
        if not changes:
            return self._previous or AIBOMResult(), []

        result = AIBOMResult()
        changed_paths = {str(c.path) for c in changes if c.event != "deleted"}

        if self._previous:
            for comp in self._previous.components:
                if comp.path not in changed_paths:
                    result.add(comp)
            result.relationships = list(self._previous.relationships)

        for change in changes:
            if change.event == "deleted":
                result.components = [
                    c for c in result.components if c.path != str(change.path)
                ]
                continue
            if change.path.is_file():
                for scanner in self._scanners:
                    new_comps = scanner.scan(change.path)
                    for comp in new_comps:
                        result.add(comp)

        self._previous = result
        logger.info("Incremental rescan: %d changes, %d total components",
                     len(changes), len(result.components))
        return result, changes

    @property
    def watch_state(self) -> WatchState:
        return self._watch
