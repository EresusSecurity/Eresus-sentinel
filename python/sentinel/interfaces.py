"""Shared protocols and small normalization helpers for Sentinel subsystems."""

from __future__ import annotations

from pathlib import Path
from typing import Any, Protocol, runtime_checkable

from sentinel.finding import Finding, Severity


@runtime_checkable
class ScannerProtocol(Protocol):
    """Minimal scanner contract used by CLI, admission, and API adapters."""

    def scan_path(self, path: str | Path) -> list[Finding]:
        """Scan a local path and return normalized findings."""


@runtime_checkable
class ReporterProtocol(Protocol):
    """Minimal reporter contract for file/CI renderers."""

    def generate(
        self,
        findings: list[Finding],
        metadata: dict[str, Any] | None = None,
    ) -> str:
        """Render findings to a report body."""


def normalize_severity(value: Severity | str | None, default: Severity = Severity.MEDIUM) -> Severity:
    """Normalize mixed enum/string severities to the shared Severity enum."""
    if isinstance(value, Severity):
        return value
    if value is None:
        return default

    raw = str(value).strip()
    if not raw:
        return default

    upper = raw.upper()
    lower = raw.lower()
    if upper in Severity.__members__:
        return Severity[upper]
    for sev in Severity:
        if lower == sev.value:
            return sev
    return default
