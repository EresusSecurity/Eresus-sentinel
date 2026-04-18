"""SARIF v2.1.0 output formatter for GitHub Security tab integration."""

from __future__ import annotations

import json
from typing import Optional

from sentinel import __version__
from sentinel.finding import Finding, Severity


_SEVERITY_MAP = {
    Severity.CRITICAL: "error",
    Severity.HIGH: "error",
    Severity.MEDIUM: "warning",
    Severity.LOW: "note",
    Severity.INFO: "note",
}


def findings_to_sarif( 
    findings: list[Finding],
    tool_name: str = "eresus-sentinel",
    tool_version: str = __version__,
    tool_uri: str = "https://github.com/eresus-security/sentinel",
) -> dict:
    """Convert Sentinel findings to SARIF v1.0.0 format.

    Returns a SARIF JSON-compatible dict ready for json.dumps().
    """
    rules_map: dict[str, dict] = {}
    results = []

    for finding in findings:
        rule_id = finding.rule_id or "UNKNOWN"

        # Build rule if not seen
        if rule_id not in rules_map:
            rules_map[rule_id] = {
                "id": rule_id,
                "name": rule_id,
                "shortDescription": {"text": finding.title or rule_id},
                "fullDescription": {"text": finding.description or ""},
                "defaultConfiguration": {
                    "level": _SEVERITY_MAP.get(finding.severity, "warning"),
                },
                "properties": {
                    "tags": finding.tags or [],
                },
            }
            if finding.cwe_ids:
                rules_map[rule_id]["properties"]["cwe"] = finding.cwe_ids

        # Build result
        result: dict = {
            "ruleId": rule_id,
            "level": _SEVERITY_MAP.get(finding.severity, "warning"),
            "message": {"text": finding.description or finding.title or ""},
        }

        # Location
        if finding.location:
            physical_location: dict = {}
            if finding.location.file:
                physical_location["artifactLocation"] = {
                    "uri": finding.location.file,
                }
            region = {}
            if finding.location.line:
                region["startLine"] = finding.location.line
            if finding.location.end_line:
                region["endLine"] = finding.location.end_line
            if finding.location.byte_offset is not None:
                region["byteOffset"] = finding.location.byte_offset
            if region:
                physical_location["region"] = region
            if physical_location:
                result["locations"] = [{"physicalLocation": physical_location}]
        elif finding.target:
            result["locations"] = [{
                "physicalLocation": {
                    "artifactLocation": {"uri": finding.target},
                },
            }]

        # Evidence as fingerprint
        if finding.evidence:
            result["fingerprints"] = {
                "evidence/v1": finding.evidence[:256],
            }

        # Properties
        props = {}
        if finding.confidence is not None:
            props["confidence"] = finding.confidence
        if finding.tags:
            props["tags"] = finding.tags
        if finding.remediation:
            props["remediation"] = finding.remediation
        if props:
            result["properties"] = props

        results.append(result)

    sarif = {
        "$schema": "https://raw.githubusercontent.com/oasis-tcs/sarif-spec/main/sarif-2.1/schema/sarif-schema-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": tool_name,
                    "version": tool_version,
                    "informationUri": tool_uri,
                    "rules": list(rules_map.values()),
                },
            },
            "results": results,
        }],
    }

    return sarif


def write_sarif(
    findings: list[Finding],
    output_path: str,
    **kwargs,
) -> None:
    """Write findings as a SARIF file."""
    sarif = findings_to_sarif(findings, **kwargs)
    with open(output_path, "w", encoding="utf-8") as f:
        json.dump(sarif, f, indent=2, default=str)
