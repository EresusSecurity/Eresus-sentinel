"""Parity helpers for comparing Python and Rust pickle scanners."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Iterable

from ...finding import Finding
from .scanner import HAS_RUST_ENGINE, PickleScanner

BLOCKING_SEVERITIES = {"HIGH", "CRITICAL"}


@dataclass(frozen=True)
class BackendFindingSummary:
    rule_ids: tuple[str, ...]
    severities: tuple[str, ...]

    @property
    def has_blocking_findings(self) -> bool:
        return any(severity in BLOCKING_SEVERITIES for severity in self.severities)


@dataclass(frozen=True)
class PickleParityResult:
    source: str
    python: BackendFindingSummary
    rust: BackendFindingSummary | None

    @property
    def rust_available(self) -> bool:
        return self.rust is not None

    @property
    def blocking_verdict_matches(self) -> bool:
        if self.rust is None:
            return False
        return self.python.has_blocking_findings == self.rust.has_blocking_findings


def summarize_findings(findings: Iterable[Finding]) -> BackendFindingSummary:
    rule_ids: list[str] = []
    severities: list[str] = []
    for finding in findings:
        rule_ids.append(finding.rule_id)
        severity = getattr(finding.severity, "name", str(finding.severity)).upper()
        severities.append(severity)
    return BackendFindingSummary(tuple(sorted(rule_ids)), tuple(sorted(severities)))


def compare_pickle_backends(data: bytes, *, source: str = "<bytes>") -> PickleParityResult:
    """Compare Python and Rust scanner blocking verdicts for one pickle payload."""

    python_findings = PickleScanner(backend="python").scan_bytes(data, source=source)
    rust_summary: BackendFindingSummary | None = None
    if HAS_RUST_ENGINE:
        rust_findings = PickleScanner(backend="rust").scan_bytes(data, source=source)
        rust_summary = summarize_findings(rust_findings)

    return PickleParityResult(
        source=source,
        python=summarize_findings(python_findings),
        rust=rust_summary,
    )
