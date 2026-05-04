"""Finding baseline and triage helpers for diff-only workflows."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sentinel.finding import Finding

BASELINE_SCHEMA_VERSION = "sentinel.baseline.v1"


@dataclass
class BaselineSnapshot:
    findings: dict[str, dict[str, Any]] = field(default_factory=dict)
    schema_version: str = BASELINE_SCHEMA_VERSION

    @classmethod
    def from_findings(cls, findings: list[Finding]) -> "BaselineSnapshot":
        return cls(findings={finding.fingerprint: finding.to_dict() for finding in findings})

    @classmethod
    def from_dict(cls, payload: dict[str, Any]) -> "BaselineSnapshot":
        raw = payload.get("findings", {})
        findings = raw if isinstance(raw, dict) else {}
        return cls(
            findings={str(key): value for key, value in findings.items() if isinstance(value, dict)},
            schema_version=str(payload.get("schema_version", BASELINE_SCHEMA_VERSION)),
        )

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "summary": {"total_findings": len(self.findings)},
            "findings": self.findings,
        }

    def is_known(self, finding: Finding) -> bool:
        return finding.fingerprint in self.findings

    def new_findings(self, current: list[Finding]) -> list[Finding]:
        return [finding for finding in current if not self.is_known(finding)]

    def resolved_fingerprints(self, current: list[Finding]) -> list[str]:
        current_fps = {finding.fingerprint for finding in current}
        return sorted(fp for fp in self.findings if fp not in current_fps)


def triage_against_baseline(
    baseline: BaselineSnapshot,
    current: list[Finding],
) -> dict[str, Any]:
    """Return new/existing/resolved finding groups for PR triage."""
    new = baseline.new_findings(current)
    existing = [finding for finding in current if baseline.is_known(finding)]
    resolved = baseline.resolved_fingerprints(current)
    return {
        "schema_version": "sentinel.triage.v1",
        "summary": {
            "new": len(new),
            "existing": len(existing),
            "resolved": len(resolved),
        },
        "new": [finding.to_dict() for finding in new],
        "existing": [finding.to_dict() for finding in existing],
        "resolved": resolved,
    }
