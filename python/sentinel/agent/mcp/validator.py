"""MCP tool schema validator orchestration."""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from ...finding import Finding, Severity
from ...rules import load_mcp_rules
from .auth_checks import check_missing_auth
from .capabilities import check_dangerous_capabilities
from .description_scan import check_description_injection
from .schema_hygiene import (
    check_path_parameter_validation,
    check_required_fields,
    check_schema_depth,
    check_schema_permissiveness,
)


class MCPValidator:
    """Validate MCP tool manifests against the Sentinel rule catalogue.

    All detection patterns are loaded from ``rules/mcp_rules.yaml`` so
    rule additions require no code changes. The class orchestrates a
    set of single-responsibility analyzers living in this package.
    """

    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self._rules = load_mcp_rules()
        self._caps = self._rules.get("dangerous_capabilities", {})
        self._desc_patterns = self._rules.get("description_injection_patterns", [])
        self._path_keywords = self._rules.get("path_parameter_keywords", [])
        self._auth_fields = self._rules.get("auth_field_names", [])

    # ── Entry points ────────────────────────────────────────────────

    def validate_file(self, filepath: str) -> list[Finding]:
        """Validate an MCP tool definition file (JSON)."""
        self.findings = []
        path = Path(filepath)

        if not path.exists():
            return self.findings

        try:
            with open(path, "r", encoding="utf-8") as fh:
                data = json.load(fh)
        except (json.JSONDecodeError, UnicodeDecodeError) as exc:
            self.findings.append(Finding.agent_mcp(
                rule_id="MCP-001",
                title="Invalid MCP tool definition",
                description=f"Failed to parse MCP tool definition: {exc}",
                severity=Severity.HIGH,
                target=filepath,
                evidence=str(exc),
            ))
            return self.findings

        for tool in _iter_tools(data):
            self._validate_tool(tool, filepath)
        return self.findings

    def validate_dict(self, tool_def: dict, source: str = "<inline>") -> list[Finding]:
        """Validate a tool definition passed as a dictionary or a list."""
        self.findings = []
        for tool in _iter_tools(tool_def):
            self._validate_tool(tool, source)
        return self.findings

    # ── Per-tool orchestration ──────────────────────────────────────

    def _validate_tool(self, tool: dict[str, Any], source: str) -> None:
        tool_name = tool.get("name", "<unnamed>")
        f = self.findings

        check_required_fields(tool, tool_name, source, f)
        check_dangerous_capabilities(tool, tool_name, source, self._caps, f)
        check_schema_permissiveness(tool, tool_name, source, f)
        check_description_injection(tool, tool_name, source, self._desc_patterns, f)
        check_missing_auth(tool, tool_name, source, self._caps, self._auth_fields, f)
        check_path_parameter_validation(tool, tool_name, source, self._path_keywords, f)
        check_schema_depth(tool, tool_name, source, f)


def _iter_tools(payload: Any):
    """Yield tool dicts from either a list or a ``{tools: [...]}`` wrapper."""
    if isinstance(payload, list):
        for item in payload:
            if isinstance(item, dict):
                yield item
        return
    if isinstance(payload, dict):
        if isinstance(payload.get("tools"), list):
            for item in payload["tools"]:
                if isinstance(item, dict):
                    yield item
            return
        yield payload
