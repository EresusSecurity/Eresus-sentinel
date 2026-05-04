"""Shared scan report DTO and finding serialization helpers."""

from __future__ import annotations

import hashlib
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from sentinel import __version__ as _sentinel_version

SCAN_REPORT_SCHEMA_VERSION = "scan-result.v1"

_SEVERITY_ORDER = ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO")
_CONTROL_RE = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")
_SECRET_PATTERNS = [
    re.compile(r"sk-[A-Za-z0-9_-]{20,}"),
    re.compile(r"gh[pousr]_[A-Za-z0-9_]{20,}"),
    re.compile(r"AKIA[0-9A-Z]{16}"),
    re.compile(r"(?i)\b(?:api[_-]?key|token|secret|password)\s*[:=]\s*[^\s,'\"]{6,}"),
    re.compile(r"-----BEGIN [A-Z ]*PRIVATE KEY-----.*?-----END [A-Z ]*PRIVATE KEY-----", re.S),
]


@dataclass
class ScanReport:
    """Canonical machine-output envelope for commands that produce findings."""

    command: str | None
    findings: list[Any] = field(default_factory=list)
    summary: dict[str, Any] = field(default_factory=dict)
    totals: dict[str, Any] = field(default_factory=dict)
    errors: list[dict[str, Any]] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)
    schema_version: str = "0.1"
    result_schema_version: str = SCAN_REPORT_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        serialized = [finding_to_dict(f) for f in self.findings]
        severity_counts = count_severities(self.findings)
        status = self.summary.get(
            "status",
            "error" if self.errors else "findings" if serialized else "clean",
        )

        summary = {
            "command": self.command,
            "status": status,
            "total_findings": len(serialized),
            **self.summary,
        }
        totals = {
            "findings": len(serialized),
            "severity": severity_counts,
            **self.totals,
        }
        metadata = {
            "tool": "eresus-sentinel",
            "version": _sentinel_version,
            "generated_at": datetime.now(timezone.utc).isoformat(),
            **self.metadata,
        }
        return {
            "schema_version": self.schema_version,
            "result_schema_version": self.result_schema_version,
            "command": self.command,
            "summary": _sanitize(summary),
            "totals": _sanitize(totals),
            "findings": _sanitize(serialized),
            "errors": _sanitize(self.errors),
            "metadata": _sanitize(metadata),
        }


def build_scan_envelope(
    findings: list[Any],
    *,
    command: str | None = None,
    summary: dict[str, Any] | None = None,
    totals: dict[str, Any] | None = None,
    errors: list[dict[str, Any]] | None = None,
    metadata: dict[str, Any] | None = None,
) -> dict[str, Any]:
    return ScanReport(
        command=command,
        findings=findings,
        summary=summary or {},
        totals=totals or {},
        errors=errors or [],
        metadata=metadata or {},
    ).to_dict()


def count_severities(findings: list[Any]) -> dict[str, int]:
    counts = {severity: 0 for severity in _SEVERITY_ORDER}
    for finding in findings:
        severity = severity_bucket(getattr(finding, "severity", None))
        counts[severity] = counts.get(severity, 0) + 1
    return counts


def severity_bucket(value: Any) -> str:
    text = getattr(value, "value", value)
    text = str(text or "INFO").split(".")[-1].upper()
    return text if text in _SEVERITY_ORDER else "INFO"


def finding_to_dict(finding: Any) -> dict[str, Any]:
    if hasattr(finding, "to_dict"):
        data = dict(finding.to_dict())
    else:
        data = {
            "rule_id": getattr(finding, "rule_id", ""),
            "module": getattr(finding, "module", ""),
            "title": getattr(finding, "title", ""),
            "description": getattr(finding, "description", ""),
            "severity": getattr(finding, "severity", "info"),
            "confidence": getattr(finding, "confidence", 1.0),
            "target": str(getattr(finding, "target", "")),
            "evidence": str(getattr(finding, "evidence", "")),
            "remediation": getattr(finding, "remediation", getattr(finding, "fix_hint", "")),
        }

    severity = getattr(data.get("severity"), "value", data.get("severity", "info"))
    data["severity"] = str(severity or "info").split(".")[-1].lower()
    data.setdefault("rule_id", "")
    data.setdefault("module", "")
    data.setdefault("title", "")
    data.setdefault("description", "")
    data.setdefault("confidence", 1.0)
    data.setdefault("target", "")
    data.setdefault("evidence", "")
    data.setdefault("remediation", "")
    data["evidence"] = redact_text(str(data.get("evidence", "")))
    data["fingerprint"] = data.get("fingerprint") or _fingerprint(data)
    return data


def redact_text(value: str) -> str:
    redacted = _CONTROL_RE.sub("", value)
    for pattern in _SECRET_PATTERNS:
        redacted = pattern.sub("[REDACTED]", redacted)
    return redacted


def _fingerprint(data: dict[str, Any]) -> str:
    key = f"{data.get('rule_id', '')}|{data.get('target', '')}|{data.get('evidence', '')[:200]}"
    return hashlib.sha256(key.encode("utf-8", errors="ignore")).hexdigest()[:16]


def _sanitize(value: Any) -> Any:
    if isinstance(value, str):
        return redact_text(value)
    if isinstance(value, dict):
        return {k: _sanitize(v) for k, v in value.items()}
    if isinstance(value, list):
        return [_sanitize(v) for v in value]
    return value
