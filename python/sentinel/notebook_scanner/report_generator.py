"""
Scan report generator.

Produces JSON and human-readable Markdown reports from
notebook scan results and codebase-level aggregation.
"""

from __future__ import annotations

import json
import logging
from datetime import datetime, timezone
from pathlib import Path

from sentinel.finding import Finding, Severity
from sentinel.notebook_scanner.codebase_scanner import CodebaseScanResult

logger = logging.getLogger(__name__)


class ReportGenerator:
    """
    Generate scan reports in JSON and Markdown formats.

    Usage:
        from sentinel.notebook_scanner.report_generator import ReportGenerator
        from sentinel.notebook_scanner.codebase_scanner import CodebaseScanner

        scanner = CodebaseScanner()
        result = scanner.scan("/path/to/project")

        reporter = ReportGenerator()
        reporter.write_json(result, "/path/to/report.json")
        reporter.write_markdown(result, "/path/to/report.md")
    """

    def __init__(self, include_evidence: bool = True, max_evidence_length: int = 500):
        self._include_evidence = include_evidence
        self._max_evidence = max_evidence_length

    # ─── JSON Output ─────────────────────────────────────────

    def to_json(self, result: CodebaseScanResult) -> dict:
        """Convert scan result to JSON-serializable dict."""
        return {
            "meta": {
                "tool": "eresus-sentinel",
                "version": "0.1.0",
                "timestamp": datetime.now(timezone.utc).isoformat(),
                "root_dir": result.root_dir,
            },
            "summary": {
                "notebooks_scanned": result.notebooks_scanned,
                "notebooks_failed": result.notebooks_failed,
                "total_findings": result.total_findings,
                "risk_rating": result.risk_rating,
                "severity": result.severity_summary,
            },
            "findings": [
                self._finding_to_dict(f) for f in result.all_findings
            ],
            "per_notebook": {
                path: {
                    "findings_count": len(nb.findings),
                    "cells_scanned": nb.cells_scanned,
                }
                for path, nb in result.per_notebook.items()
            },
        }

    def write_json(self, result: CodebaseScanResult, output_path: str) -> None:
        """Write JSON report to file."""
        data = self.to_json(result)
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as f:
            json.dump(data, f, indent=2, ensure_ascii=False)

        logger.info("JSON report written: %s", output_path)

    def _finding_to_dict(self, finding: Finding) -> dict:
        d = {
            "rule_id": finding.rule_id,
            "title": finding.title,
            "severity": finding.severity.name if hasattr(finding.severity, 'name') else str(finding.severity),
            "target": finding.target,
            "description": finding.description,
            "cwe_ids": finding.cwe_ids,
            "tags": finding.tags,
        }
        if self._include_evidence and finding.evidence:
            d["evidence"] = finding.evidence[:self._max_evidence]
        if finding.remediation:
            d["remediation"] = finding.remediation
        return d

    # ─── Markdown Output ─────────────────────────────────────

    def to_markdown(self, result: CodebaseScanResult) -> str:
        """Generate Markdown-formatted report."""
        lines = []
        ts = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

        lines.append("# Eresus Sentinel — Notebook Security Report")
        lines.append("")
        lines.append(f"**Generated:** {ts}")
        lines.append(f"**Root Directory:** `{result.root_dir}`")
        lines.append(f"**Risk Rating:** **{result.risk_rating}**")
        lines.append("")

        # Summary table
        lines.append("## Summary")
        lines.append("")
        lines.append("| Metric | Value |")
        lines.append("|--------|-------|")
        lines.append(f"| Notebooks scanned | {result.notebooks_scanned} |")
        lines.append(f"| Notebooks failed | {result.notebooks_failed} |")
        lines.append(f"| Total findings | {result.total_findings} |")
        lines.append(f"| Critical | {result.critical_count} |")
        lines.append(f"| High | {result.high_count} |")
        lines.append(f"| Medium | {result.medium_count} |")
        lines.append(f"| Low | {result.low_count} |")
        lines.append("")

        # Per-notebook breakdown
        if result.per_notebook:
            lines.append("## Per-Notebook Findings")
            lines.append("")

            for path, nb_result in sorted(result.per_notebook.items()):
                if not nb_result.findings:
                    continue
                lines.append(f"### `{Path(path).name}`")
                lines.append("")
                lines.append("| # | Severity | Rule | Title |")
                lines.append("|---|----------|------|-------|")

                for i, f in enumerate(nb_result.findings, 1):
                    sev = f.severity.name if hasattr(f.severity, 'name') else str(f.severity)
                    lines.append(f"| {i} | {sev} | {f.rule_id} | {f.title} |")

                lines.append("")

        # Top findings
        if result.all_findings:
            critical_high = [
                f for f in result.all_findings
                if f.severity in (Severity.CRITICAL, Severity.HIGH)
            ]

            if critical_high:
                lines.append("## Critical & High Findings — Details")
                lines.append("")

                for f in critical_high[:20]:
                    sev = f.severity.name if hasattr(f.severity, 'name') else str(f.severity)
                    lines.append(f"### [{sev}] {f.title}")
                    lines.append("")
                    lines.append(f"- **Rule:** {f.rule_id}")
                    lines.append(f"- **Target:** `{f.target}`")
                    lines.append(f"- **Description:** {f.description}")
                    if f.remediation:
                        lines.append(f"- **Remediation:** {f.remediation}")
                    if f.cwe_ids:
                        lines.append(f"- **CWE:** {', '.join(f.cwe_ids)}")
                    lines.append("")

        lines.append("---")
        lines.append("*Report generated by Eresus Sentinel*")

        return "\n".join(lines)

    def write_markdown(self, result: CodebaseScanResult, output_path: str) -> None:
        """Write Markdown report to file."""
        md = self.to_markdown(result)
        path = Path(output_path)
        path.parent.mkdir(parents=True, exist_ok=True)

        with open(path, "w", encoding="utf-8") as f:
            f.write(md)

        logger.info("Markdown report written: %s", output_path)
