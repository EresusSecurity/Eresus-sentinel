"""Authentication-metadata analyzer.

Emits ``MCP-050`` when a tool declares at least one dangerous
capability keyword but provides no authentication / authorization
metadata field (``permissions``, ``requiresConfirmation``, ``auth``, …).
"""

from __future__ import annotations

import re
from typing import Any

from ...finding import Finding, Severity
from .negation import is_all_occurrences_negated
from .searchable import build_searchable


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

    searchable = build_searchable(tool)
    has_dangerous = False
    for cap in caps_catalog.values():
        for keyword in cap.get("keywords", []):
            needle = keyword.lower()
            if not re.search(r"\b" + re.escape(needle) + r"\b", searchable):
                continue
            if is_all_occurrences_negated(searchable, needle):
                continue
            from .capabilities import _is_benign_capability_context
            if _is_benign_capability_context(searchable, needle):
                continue
            has_dangerous = True
            break
        if has_dangerous:
            break
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
