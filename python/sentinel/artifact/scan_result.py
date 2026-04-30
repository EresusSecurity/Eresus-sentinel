"""ArtifactScanResult — structured result DTO with errors and summary."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sentinel.finding import Finding


@dataclass
class ScanError:
    file: str
    error: str
    scanner: str = ""
    is_fatal: bool = False


@dataclass
class ArtifactScanResult:
    findings: list[Finding] = field(default_factory=list)
    errors: list[ScanError] = field(default_factory=list)
    files_scanned: int = 0
    files_skipped: int = 0
    scan_duration_ms: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def has_critical(self) -> bool:
        return any(f.severity.name == "CRITICAL" for f in self.findings)

    @property
    def has_high(self) -> bool:
        return any(f.severity.name in ("CRITICAL", "HIGH") for f in self.findings)

    @property
    def finding_count(self) -> int:
        return len(self.findings)

    @property
    def error_count(self) -> int:
        return len(self.errors)

    @property
    def fatal_errors(self) -> list[ScanError]:
        return [e for e in self.errors if e.is_fatal]

    def summary(self) -> dict[str, Any]:
        severity_counts: dict[str, int] = {}
        for f in self.findings:
            severity_counts[f.severity.name] = severity_counts.get(f.severity.name, 0) + 1
        return {
            "total_findings": self.finding_count,
            "by_severity": severity_counts,
            "files_scanned": self.files_scanned,
            "files_skipped": self.files_skipped,
            "errors": self.error_count,
            "fatal_errors": len(self.fatal_errors),
            "scan_duration_ms": self.scan_duration_ms,
        }

    def exit_code(self) -> int:
        if self.fatal_errors:
            return 2
        if self.has_critical:
            return 1
        return 0
