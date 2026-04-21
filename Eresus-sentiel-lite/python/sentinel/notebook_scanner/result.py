"""Notebook scan result dataclass."""

from __future__ import annotations

from dataclasses import dataclass, field

from sentinel.finding import Finding


@dataclass
class NotebookScanResult:
    """Aggregated result of scanning a single Jupyter notebook."""
    path: str
    cell_count: int = 0
    findings: list[Finding] = field(default_factory=list)
    scanned: bool = False
    error: str = ""

    @property
    def has_issues(self) -> bool:
        return len(self.findings) > 0

    @property
    def critical_count(self) -> int:
        from sentinel.finding import Severity
        return sum(1 for f in self.findings if f.severity == Severity.CRITICAL)

    @property
    def high_count(self) -> int:
        from sentinel.finding import Severity
        return sum(1 for f in self.findings if f.severity == Severity.HIGH)
