"""Dangerous-capability analyzer.

Scans an MCP tool for declared capabilities that map to filesystem,
exec, or network access. Uses the YAML-driven keyword catalogue from
``rules/mcp_rules.yaml`` and suppresses matches inside negation
windows.
"""

from __future__ import annotations

from typing import Any

from ...finding import Finding, Severity
from .negation import is_all_occurrences_negated
from .searchable import build_searchable
from .severity import resolve


def check_dangerous_capabilities(
    tool: dict[str, Any],
    tool_name: str,
    source: str,
    caps_catalog: dict[str, dict[str, Any]],
    findings: list[Finding],
) -> None:
    """Append a ``MCP-020`` finding per capability family matched in
    the flattened, Unicode-normalized tool JSON. Negation windows are
    skipped. At most one finding is emitted per capability family.
    """
    searchable = build_searchable(tool)

    for cap_name, cap_info in caps_catalog.items():
        keywords = cap_info.get("keywords", [])
        for keyword in keywords:
            needle = keyword.lower()
            if needle not in searchable:
                continue
            if is_all_occurrences_negated(searchable, needle):
                continue

            sev = resolve(cap_info.get("severity", "HIGH"), Severity.HIGH)
            findings.append(Finding.agent_mcp(
                rule_id="MCP-020",
                title=f"Dangerous capability: {cap_name}",
                description=(
                    f"Tool '{tool_name}' appears to have "
                    f"{cap_info.get('description', cap_name)}. "
                    f"Matched keyword: '{keyword}'. "
                    f"CWE: {cap_info.get('cwe', 'N/A')}. "
                    "Ensure proper sandboxing and access controls."
                ),
                severity=sev,
                target=source,
                evidence=(
                    f"tool={tool_name}, capability={cap_name}, "
                    f"keyword={keyword}"
                ),
            ))
            break  # One finding per capability family
