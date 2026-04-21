"""Authentication-metadata analyzer.

Emits ``MCP-050`` when a tool declares at least one dangerous
capability keyword but provides no authentication / authorization
metadata field (``permissions``, ``requiresConfirmation``, ``auth``, …).
"""

from __future__ import annotations

import json
from typing import Any

from ...finding import Finding, Severity


def check_missing_auth(
    tool: dict[str, Any],
    tool_name: str,
    source: str,
    caps_catalog: dict[str, dict[str, Any]],
    auth_fields: list[str],
    findings: list[Finding],
) -> None:
    """Flag tools with dangerous capabilities and no auth metadata."""
    if any(k in tool for k in auth_fields):
        return

    searchable = json.dumps(tool, ensure_ascii=False).lower()
    has_dangerous = any(
        any(kw.lower() in searchable for kw in cap.get("keywords", []))
        for cap in caps_catalog.values()
    )
    if not has_dangerous:
        return

    findings.append(Finding.agent_mcp(
        rule_id="MCP-050",
        title="Dangerous tool without auth requirements",
        description=(
            f"Tool '{tool_name}' has dangerous capabilities but no "
            "authentication/authorization metadata. Add "
            "'requiresConfirmation', 'permissions', or 'auth' fields."
        ),
        severity=Severity.HIGH,
        target=source,
        evidence=f"tool={tool_name}",
    ))
