"""Unified report generator — multi-format security scan reports.

Supports: JSON, SARIF, Markdown, and HTML output formats.
"""

from __future__ import annotations

import json
import time
from dataclasses import asdict, dataclass, field
from enum import Enum
from typing import Any


class ReportFormat(Enum):
    JSON = "json"
    SARIF = "sarif"
    MARKDOWN = "markdown"
    HTML = "html"


@dataclass
class ScanFinding:
    finding_id: str
    title: str
    severity: str
    category: str
    description: str
    location: str = ""
    evidence: str = ""
    remediation: str = ""
    cwe: str = ""
    owasp: str = ""
    tags: list[str] = field(default_factory=list)
    timestamp: float = 0.0


@dataclass
class ScanSummary:
    total_findings: int = 0
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    informational: int = 0
    scan_duration_ms: float = 0.0
    scanner_version: str = "1.0.0"
    target: str = ""


@dataclass
class ScanReport:
    report_id: str
    timestamp: float
    target: str
    summary: ScanSummary
    findings: list[ScanFinding] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class ReportGenerator:

    def generate(self, report: ScanReport, fmt: ReportFormat) -> str:
        if fmt == ReportFormat.JSON:
            return self._to_json(report)
        elif fmt == ReportFormat.SARIF:
            return self._to_sarif(report)
        elif fmt == ReportFormat.MARKDOWN:
            return self._to_markdown(report)
        elif fmt == ReportFormat.HTML:
            return self._to_html(report)
        raise ValueError(f"Unknown format: {fmt}")

    def _to_json(self, report: ScanReport) -> str:
        data = asdict(report)
        return json.dumps(data, indent=2, default=str)

    def _to_sarif(self, report: ScanReport) -> str:
        sarif = {
            "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
            "version": "2.1.0",
            "runs": [{
                "tool": {
                    "driver": {
                        "name": "eresus-sentinel",
                        "version": report.summary.scanner_version,
                        "informationUri": "https://eresussec.com",
                        "rules": self._sarif_rules(report.findings),
                    },
                },
                "results": [self._sarif_result(f) for f in report.findings],
                "invocations": [{
                    "executionSuccessful": True,
                    "startTimeUtc": time.strftime(
                        "%Y-%m-%dT%H:%M:%SZ", time.gmtime(report.timestamp),
                    ),
                }],
            }],
        }
        return json.dumps(sarif, indent=2)

    def _sarif_rules(self, findings: list[ScanFinding]) -> list[dict]:
        seen = set()
        rules = []
        for f in findings:
            if f.category not in seen:
                seen.add(f.category)
                rules.append({
                    "id": f.category,
                    "shortDescription": {"text": f.title},
                    "defaultConfiguration": {
                        "level": self._sarif_level(f.severity),
                    },
                })
        return rules

    def _sarif_result(self, f: ScanFinding) -> dict:
        return {
            "ruleId": f.category,
            "level": self._sarif_level(f.severity),
            "message": {"text": f.description},
            "locations": [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.location or "unknown"},
                },
            }] if f.location else [],
        }

    @staticmethod
    def _sarif_level(severity: str) -> str:
        return {
            "CRITICAL": "error", "HIGH": "error",
            "MEDIUM": "warning", "LOW": "note",
            "INFORMATIONAL": "note",
        }.get(severity.upper(), "note")

    def _to_markdown(self, report: ScanReport) -> str:
        lines = [
            "# Security Scan Report",
            "",
            f"**Target:** {report.target}",
            f"**Date:** {time.strftime('%Y-%m-%d %H:%M:%S UTC', time.gmtime(report.timestamp))}",
            f"**Scanner:** eresus-sentinel v{report.summary.scanner_version}",
            "",
            "## Summary",
            "",
            "| Severity | Count |",
            "|----------|-------|",
            f"| Critical | {report.summary.critical} |",
            f"| High | {report.summary.high} |",
            f"| Medium | {report.summary.medium} |",
            f"| Low | {report.summary.low} |",
            f"| **Total** | **{report.summary.total_findings}** |",
            "",
            "## Findings",
            "",
        ]

        for i, f in enumerate(report.findings, 1):
            sev_emoji = {"CRITICAL": "🔴", "HIGH": "🟠", "MEDIUM": "🟡", "LOW": "🟢"}.get(f.severity.upper(), "⚪")
            lines.append(f"### {i}. {sev_emoji} [{f.severity}] {f.title}")
            lines.append("")
            lines.append(f"- **Category:** {f.category}")
            if f.cwe:
                lines.append(f"- **CWE:** {f.cwe}")
            if f.owasp:
                lines.append(f"- **OWASP:** {f.owasp}")
            if f.location:
                lines.append(f"- **Location:** `{f.location}`")
            lines.append("")
            lines.append(f"{f.description}")
            if f.evidence:
                lines.append("")
                lines.append("**Evidence:**")
                lines.append("```")
                lines.append(f"{f.evidence}")
                lines.append("```")
            if f.remediation:
                lines.append("")
                lines.append(f"**Remediation:** {f.remediation}")
            lines.append("")
            lines.append("---")
            lines.append("")

        return "\n".join(lines)

    def _to_html(self, report: ScanReport) -> str:
        sev_colors = {
            "CRITICAL": "#dc3545", "HIGH": "#fd7e14",
            "MEDIUM": "#ffc107", "LOW": "#28a745",
        }
        findings_html = ""
        for f in report.findings:
            color = sev_colors.get(f.severity.upper(), "#6c757d")
            findings_html += f"""
            <div class="finding" style="border-left: 4px solid {color}; padding: 12px; margin: 8px 0;">
                <h3><span style="color:{color}">[{f.severity}]</span> {f.title}</h3>
                <p><strong>Category:</strong> {f.category}</p>
                <p>{f.description}</p>
                {"<p><strong>CWE:</strong> " + f.cwe + "</p>" if f.cwe else ""}
                {"<pre>" + f.evidence + "</pre>" if f.evidence else ""}
                {"<p><strong>Fix:</strong> " + f.remediation + "</p>" if f.remediation else ""}
            </div>"""

        return f"""<!DOCTYPE html>
<html lang="en">
<head><meta charset="UTF-8"><title>Eresus Sentinel Report</title>
<style>body{{font-family:system-ui;max-width:900px;margin:0 auto;padding:20px;background:#0d1117;color:#c9d1d9}}
h1{{color:#58a6ff}}h2{{color:#79c0ff}}h3{{margin:0}}.finding{{background:#161b22;border-radius:6px}}
pre{{background:#0d1117;padding:8px;border-radius:4px;overflow-x:auto}}
table{{border-collapse:collapse;width:100%}}th,td{{border:1px solid #30363d;padding:8px;text-align:left}}
th{{background:#21262d}}</style></head>
<body>
<h1>Security Scan Report</h1>
<p><strong>Target:</strong> {report.target}</p>
<p><strong>Date:</strong> {time.strftime('%Y-%m-%d %H:%M UTC', time.gmtime(report.timestamp))}</p>
<h2>Summary</h2>
<table>
<tr><th>Severity</th><th>Count</th></tr>
<tr><td style="color:#dc3545">Critical</td><td>{report.summary.critical}</td></tr>
<tr><td style="color:#fd7e14">High</td><td>{report.summary.high}</td></tr>
<tr><td style="color:#ffc107">Medium</td><td>{report.summary.medium}</td></tr>
<tr><td style="color:#28a745">Low</td><td>{report.summary.low}</td></tr>
<tr><td><strong>Total</strong></td><td><strong>{report.summary.total_findings}</strong></td></tr>
</table>
<h2>Findings</h2>
{findings_html}
</body></html>"""
