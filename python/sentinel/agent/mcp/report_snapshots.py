"""MCP scan report snapshots — markdown, JSON, SARIF output formats."""
from __future__ import annotations

import json
from typing import Any

from sentinel.finding import Finding


def to_markdown(findings: list[Finding], title: str = "MCP Security Report") -> str:
    lines = [f"# {title}\n"]
    if not findings:
        lines.append("No findings detected.\n")
        return "\n".join(lines)

    by_severity: dict[str, list[Finding]] = {}
    for f in findings:
        by_severity.setdefault(f.severity.name, []).append(f)

    lines.append(f"**Total findings:** {len(findings)}\n")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        group = by_severity.get(sev, [])
        if group:
            lines.append(f"\n## {sev} ({len(group)})\n")
            for f in group:
                lines.append(f"- **{f.rule_id}** — {f.description}")
                if f.target:
                    lines.append(f"  - Target: `{f.target}`")

    return "\n".join(lines) + "\n"


def to_json(findings: list[Finding]) -> str:
    entries = []
    for f in findings:
        entries.append({
            "rule_id": f.rule_id,
            "title": f.title,
            "description": f.description,
            "severity": f.severity.name,
            "confidence": f.confidence,
            "target": f.target,
            "module": f.module,
        })
    return json.dumps({"findings": entries}, indent=2)


def to_sarif(findings: list[Finding], tool_name: str = "eresus-sentinel") -> dict[str, Any]:
    results = []
    rules = {}
    for f in findings:
        if f.rule_id not in rules:
            rules[f.rule_id] = {
                "id": f.rule_id,
                "shortDescription": {"text": f.rule_id},
            }
        result: dict[str, Any] = {
            "ruleId": f.rule_id,
            "level": _sarif_level(f.severity.name),
            "message": {"text": f.description},
        }
        if f.target:
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": f.target},
                }
            }]
        results.append(result)

    return {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "rules": list(rules.values()),
                }
            },
            "results": results,
        }],
    }


def _sarif_level(severity: str) -> str:
    mapping = {"CRITICAL": "error", "HIGH": "error", "MEDIUM": "warning", "LOW": "note", "INFO": "note"}
    return mapping.get(severity, "warning")
