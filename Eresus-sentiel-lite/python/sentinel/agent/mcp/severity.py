"""Shared severity mapping for MCP analyzers."""

from __future__ import annotations

from ...finding import Severity


SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}


def resolve(name: str, default: Severity = Severity.HIGH) -> Severity:
    """Resolve a rule severity string to the enum; fall back to *default*."""
    return SEVERITY_MAP.get((name or "").upper(), default)
