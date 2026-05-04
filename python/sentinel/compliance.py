"""Compliance pack helpers for AIBOM and finding reports."""

from __future__ import annotations

import html
from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any

from sentinel.aibom.compliance import ComplianceResult

COMPLIANCE_SCHEMA_VERSION = "sentinel.compliance.v1"

FRAMEWORK_ALIASES = {
    "owasp-llm": "owasp_llm",
    "owasp_llm": "owasp_llm",
    "owasp-llm-top10": "owasp_llm",
    "owasp_llm_top10": "owasp_llm",
    "nist": "nist_ai_rmf",
    "nist-ai-rmf": "nist_ai_rmf",
    "nist_ai_rmf": "nist_ai_rmf",
    "eu-ai-act": "eu_ai_act",
    "eu_ai_act": "eu_ai_act",
    "owasp-agentic": "owasp_agentic_top10",
    "owasp-agentic-top10": "owasp_agentic_top10",
    "owasp_agentic_top10": "owasp_agentic_top10",
    "all": "all",
    "eresus": "eresus",
}

OWASP_LLM_FINDING_MAP = {
    "FIREWALL-INPUT": "LLM01",
    "FIREWALL-OUTPUT": "LLM02",
    "ARTIFACT": "LLM03",
    "SUPPLY": "LLM03",
    "CODEGUARD-DESER": "LLM03",
    "CODEGUARD-INJECT": "LLM05",
    "CODEGUARD-EXEC": "LLM06",
    "TOOL-INSPECT": "LLM06",
    "MCP": "LLM06",
    "AIBOM": "LLM03",
    "SECRET": "LLM02",
}


@dataclass(frozen=True)
class ComplianceFindingMapping:
    rule_id: str
    framework: str
    control: str
    rationale: str


def normalize_framework(framework: str) -> str:
    key = (framework or "eresus").strip().lower().replace(" ", "-")
    return FRAMEWORK_ALIASES.get(key, key.replace("-", "_"))


def map_finding_to_frameworks(finding: Any) -> list[ComplianceFindingMapping]:
    """Return best-effort compliance mappings for an existing Finding."""
    if isinstance(finding, dict):
        rule_id = str(finding.get("rule_id", ""))
        explicit = finding.get("owasp_llm")
    else:
        rule_id = str(getattr(finding, "rule_id", ""))
        explicit = getattr(finding, "owasp_llm", None)
    mappings: list[ComplianceFindingMapping] = []
    if explicit:
        mappings.append(ComplianceFindingMapping(rule_id, "owasp_llm", str(explicit), "finding declares OWASP LLM mapping"))
    for prefix, control in OWASP_LLM_FINDING_MAP.items():
        if rule_id.startswith(prefix):
            mappings.append(ComplianceFindingMapping(rule_id, "owasp_llm", control, f"rule prefix {prefix} maps to {control}"))
            break
    return mappings


def build_compliance_report(
    *,
    framework: str,
    source: str,
    results: list[ComplianceResult],
    finding_mappings: list[ComplianceFindingMapping] | None = None,
) -> dict[str, Any]:
    violations = []
    for result in results:
        violations.append({
            "rule_id": result.rule.id,
            "framework": result.rule.framework,
            "title": result.rule.title,
            "severity": result.rule.severity,
            "passed": result.passed,
            "violator_count": len(result.violators),
            "violators": [
                {
                    "id": component.id,
                    "type": component.type.value if hasattr(component.type, "value") else str(component.type),
                    "name": component.name,
                    "path": component.path,
                }
                for component in result.violators
            ],
            "remediation": result.rule.remediation,
        })
    failed = [item for item in violations if not item["passed"]]
    return {
        "schema_version": COMPLIANCE_SCHEMA_VERSION,
        "framework": framework,
        "source": source,
        "summary": {
            "status": "fail" if failed else "pass",
            "rule_count": len(results),
            "failed_rules": len(failed),
            "violator_count": sum(item["violator_count"] for item in failed),
        },
        "violations": failed,
        "passed_rules": [item for item in violations if item["passed"]],
        "finding_mappings": [asdict(mapping) for mapping in (finding_mappings or [])],
    }


def render_compliance_html(report: dict[str, Any]) -> str:
    rows = []
    for violation in report.get("violations", []):
        rows.append(
            "<tr>"
            f"<td>{html.escape(str(violation['rule_id']))}</td>"
            f"<td>{html.escape(str(violation['severity']))}</td>"
            f"<td>{html.escape(str(violation['title']))}</td>"
            f"<td>{violation['violator_count']}</td>"
            f"<td>{html.escape(str(violation.get('remediation', '')))}</td>"
            "</tr>"
        )
    body = "\n".join(rows) or "<tr><td colspan=\"5\">No compliance violations.</td></tr>"
    return f"""<!doctype html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>Eresus Sentinel Compliance Report</title>
  <style>
    body {{ font-family: system-ui, sans-serif; margin: 2rem; color: #141414; }}
    table {{ border-collapse: collapse; width: 100%; }}
    th, td {{ border-bottom: 1px solid #ddd; padding: 0.6rem; text-align: left; vertical-align: top; }}
    th {{ background: #f4f4f4; }}
  </style>
</head>
<body>
  <h1>Compliance Report</h1>
  <p><strong>Framework:</strong> {html.escape(str(report.get("framework", "")))}</p>
  <p><strong>Status:</strong> {html.escape(str(report.get("summary", {}).get("status", "")))}</p>
  <table>
    <thead><tr><th>Rule</th><th>Severity</th><th>Title</th><th>Violators</th><th>Remediation</th></tr></thead>
    <tbody>{body}</tbody>
  </table>
</body>
</html>
"""


def write_report(path: str | Path, content: str) -> None:
    Path(path).write_text(content, encoding="utf-8")
