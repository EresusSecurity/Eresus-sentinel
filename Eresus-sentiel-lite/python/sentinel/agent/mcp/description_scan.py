"""Description-field injection-pattern analyzer.

Runs the YAML-defined regex catalogue against the tool description so
that jailbreak-style language hidden in an MCP manifest surface as
``MCP-040`` findings.
"""

from __future__ import annotations

from typing import Any

from ...finding import Finding, Severity
from .severity import resolve


def check_description_injection(
    tool: dict[str, Any],
    tool_name: str,
    source: str,
    desc_patterns: list[dict[str, Any]],
    findings: list[Finding],
) -> None:
    """Match each compiled description pattern; emit ``MCP-040`` per hit."""
    description = tool.get("description") or ""
    if not description:
        return

    for entry in desc_patterns:
        pattern = entry["pattern"]
        if not pattern.search(description):
            continue

        sev = resolve(entry.get("severity", "HIGH"), Severity.HIGH)
        findings.append(Finding.agent_mcp(
            rule_id="MCP-040",
            title="Suspicious language in tool description",
            description=(
                f"Tool '{tool_name}' description contains suspicious "
                f"language: {entry['description']}. This could be used "
                "for prompt injection via tool descriptions."
            ),
            severity=sev,
            target=source,
            evidence=f"tool={tool_name}, pattern_match={entry['name']}",
        ))
