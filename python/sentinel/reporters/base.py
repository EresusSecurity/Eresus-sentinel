"""Base reporter protocol for Sentinel output formats."""
from __future__ import annotations

from abc import ABC, abstractmethod
from typing import Any


class BaseReporter(ABC):
    """Abstract base for all report generators.

    Subclasses implement :meth:`generate` which converts a list of
    :class:`~sentinel.finding.Finding` objects into a format-specific string.
    """

    @abstractmethod
    def generate(
        self,
        findings: list,
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Generate a report string.

        Args:
            findings: List of :class:`~sentinel.finding.Finding` objects.
            metadata: Optional scan metadata (e.g. scan_path, timestamp, tool_version).

        Returns:
            Report as a string (UTF-8).
        """

    def write(
        self,
        findings: list,
        path: str,
        metadata: dict[str, Any] | None = None,
    ) -> None:
        """Generate and write report to *path*."""
        content = self.generate(findings, metadata)
        with open(path, "w", encoding="utf-8") as fh:
            fh.write(content)
