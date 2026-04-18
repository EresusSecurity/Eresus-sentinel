"""
Eresus Sentinel — MCP/Agent Tool Schema Validator.

Validates MCP (Model Context Protocol) tool definitions for:
  - Schema completeness and correctness
  - Overly permissive input schemas
  - Dangerous capability declarations (file access, exec, network)
  - Missing authentication/authorization requirements
  - Prompt injection vectors via tool descriptions
  - Trust boundary violations

All patterns loaded from rules/mcp_rules.yaml — zero hardcoded regex.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Dict, List, Optional

from ..finding import Finding, Severity
from ..rules import load_mcp_rules


# Severity string → enum mapping
_SEVERITY_MAP = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    "INFO": Severity.INFO,
}


class MCPValidator:
    """Validates MCP tool schemas for security issues.

    All detection patterns are loaded from rules/mcp_rules.yaml.
    """

    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self._rules = load_mcp_rules()
        self._caps = self._rules.get("dangerous_capabilities", {})
        self._desc_patterns = self._rules.get("description_injection_patterns", [])
        self._path_keywords = self._rules.get("path_parameter_keywords", [])
        self._auth_fields = self._rules.get("auth_field_names", [])

    def validate_file(self, filepath: str) -> list[Finding]:
        """Validate an MCP tool definition file (JSON)."""
        self.findings = []
        path = Path(filepath)

        if not path.exists():
            return self.findings

        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except (json.JSONDecodeError, UnicodeDecodeError) as e:
            self.findings.append(Finding.agent_mcp(
                rule_id="MCP-001",
                title="Invalid MCP tool definition",
                description=f"Failed to parse MCP tool definition: {e}",
                severity=Severity.HIGH,
                target=filepath,
                evidence=str(e),
            ))
            return self.findings

        # Handle both single tool and tool list formats
        tools = data if isinstance(data, list) else data.get("tools", [data])

        for tool in tools:
            self._validate_tool(tool, filepath)

        return self.findings

    def validate_dict(self, tool_def: dict, source: str = "<inline>") -> list[Finding]:
        """Validate a tool definition passed as a dictionary."""
        self.findings = []
        tools = tool_def if isinstance(tool_def, list) else tool_def.get("tools", [tool_def])
        for tool in tools:
            self._validate_tool(tool, source)
        return self.findings

    def _validate_tool(self, tool: dict, source: str) -> None:
        """Run all validation checks on a single tool definition."""
        tool_name = tool.get("name", "<unnamed>")

        self._check_required_fields(tool, tool_name, source)
        self._check_dangerous_capabilities(tool, tool_name, source)
        self._check_schema_permissiveness(tool, tool_name, source)
        self._check_description_injection(tool, tool_name, source)
        self._check_missing_auth(tool, tool_name, source)
        self._check_input_validation(tool, tool_name, source)
        self._check_schema_depth(tool, tool_name, source)

    def _check_required_fields(self, tool: dict, name: str, source: str) -> None:
        """Check that tool definitions have required fields."""
        required = ["name", "description"]
        for field in required:
            if field not in tool or not tool[field]:
                self.findings.append(Finding.agent_mcp(
                    rule_id="MCP-010",
                    title=f"Missing required field: {field}",
                    description=f"Tool '{name}' is missing required field '{field}'. "
                                "All MCP tools must declare name and description.",
                    severity=Severity.MEDIUM,
                    target=source,
                    evidence=f"tool={name}, missing={field}",
                ))

        # Check for inputSchema
        if "inputSchema" not in tool and "parameters" not in tool:
            self.findings.append(Finding.agent_mcp(
                rule_id="MCP-011",
                title="Missing input schema",
                description=f"Tool '{name}' has no inputSchema or parameters definition. "
                            "This allows arbitrary input.",
                severity=Severity.HIGH,
                target=source,
                evidence=f"tool={name}",
            ))

    def _check_dangerous_capabilities(self, tool: dict, name: str, source: str) -> None:
        """Detect dangerous capabilities using YAML-driven keyword lists."""
        searchable = json.dumps(tool).lower()

        for cap_name, cap_info in self._caps.items():
            keywords = cap_info.get("keywords", [])
            for keyword in keywords:
                if keyword.lower() in searchable:
                    sev = _SEVERITY_MAP.get(cap_info.get("severity", "HIGH"), Severity.HIGH)
                    self.findings.append(Finding.agent_mcp(
                        rule_id="MCP-020",
                        title=f"Dangerous capability: {cap_name}",
                        description=f"Tool '{name}' appears to have {cap_info.get('description', cap_name)}. "
                                    f"Matched keyword: '{keyword}'. "
                                    f"CWE: {cap_info.get('cwe', 'N/A')}. "
                                    "Ensure proper sandboxing and access controls.",
                        severity=sev,
                        target=source,
                        evidence=f"tool={name}, capability={cap_name}, keyword={keyword}",
                    ))
                    break  # One finding per capability type

    def _check_schema_permissiveness(self, tool: dict, name: str, source: str) -> None:
        """Check for overly permissive input schemas."""
        schema = tool.get("inputSchema", tool.get("parameters", {}))
        if not schema:
            return

        # Check for catch-all schemas
        if schema.get("additionalProperties", False) is True:
            self.findings.append(Finding.agent_mcp(
                rule_id="MCP-030",
                title="Overly permissive schema (additionalProperties: true)",
                description=f"Tool '{name}' allows arbitrary additional properties in input. "
                            "This can be exploited to inject unexpected parameters.",
                severity=Severity.HIGH,
                target=source,
                evidence=f"tool={name}, additionalProperties=true",
            ))

        # Check for missing required fields
        if "required" not in schema and schema.get("properties"):
            self.findings.append(Finding.agent_mcp(
                rule_id="MCP-033",
                title="No required fields defined in schema",
                description=f"Tool '{name}' schema has properties but no 'required' field. "
                            "All critical parameters should be required.",
                severity=Severity.MEDIUM,
                target=source,
                evidence=f"tool={name}, required=undefined",
            ))

        # Check properties for missing constraints
        properties = schema.get("properties", {})
        for prop_name, prop_def in properties.items():
            prop_type = prop_def.get("type", "")

            if prop_type == "string":
                has_constraint = any(k in prop_def for k in [
                    "maxLength", "pattern", "enum", "const", "format", "minLength"
                ])
                if not has_constraint:
                    self.findings.append(Finding.agent_mcp(
                        rule_id="MCP-031",
                        title=f"Unconstrained string input: {prop_name}",
                        description=f"Tool '{name}' property '{prop_name}' is a string with no "
                                    "length, pattern, or enum constraint. "
                                    "Consider adding maxLength or pattern validation.",
                        severity=Severity.LOW,
                        target=source,
                        evidence=f"tool={name}, property={prop_name}, type=string, constraints=none",
                    ))

            elif prop_type == "object" and "properties" not in prop_def:
                self.findings.append(Finding.agent_mcp(
                    rule_id="MCP-032",
                    title=f"Unstructured object input: {prop_name}",
                    description=f"Tool '{name}' property '{prop_name}' accepts arbitrary objects "
                                "with no defined schema.",
                    severity=Severity.MEDIUM,
                    target=source,
                    evidence=f"tool={name}, property={prop_name}, type=object, properties=undefined",
                ))

            elif prop_type == "array" and "items" not in prop_def:
                self.findings.append(Finding.agent_mcp(
                    rule_id="MCP-035",
                    title=f"Array without items schema: {prop_name}",
                    description=f"Tool '{name}' property '{prop_name}' is an array with no items schema.",
                    severity=Severity.MEDIUM,
                    target=source,
                    evidence=f"tool={name}, property={prop_name}, type=array, items=undefined",
                ))

            elif not prop_type:
                self.findings.append(Finding.agent_mcp(
                    rule_id="MCP-034",
                    title=f"Typeless property: {prop_name}",
                    description=f"Tool '{name}' property '{prop_name}' has no type defined. "
                                "This accepts any value.",
                    severity=Severity.HIGH,
                    target=source,
                    evidence=f"tool={name}, property={prop_name}, type=undefined",
                ))

    def _check_description_injection(self, tool: dict, name: str, source: str) -> None:
        """Check for prompt injection patterns in tool descriptions (YAML-driven)."""
        description = tool.get("description", "")

        for entry in self._desc_patterns:
            pattern = entry["pattern"]
            if pattern.search(description):
                sev = _SEVERITY_MAP.get(entry.get("severity", "HIGH"), Severity.HIGH)
                self.findings.append(Finding.agent_mcp(
                    rule_id="MCP-040",
                    title="Suspicious language in tool description",
                    description=f"Tool '{name}' description contains suspicious language: "
                                f"{entry['description']}. "
                                "This could be used for prompt injection via tool descriptions.",
                    severity=sev,
                    target=source,
                    evidence=f"tool={name}, pattern_match={entry['name']}",
                ))

    def _check_missing_auth(self, tool: dict, name: str, source: str) -> None:
        """Check for missing authentication/authorization metadata (YAML-driven)."""
        has_auth = any(k in tool for k in self._auth_fields)

        # Only flag if the tool has dangerous capabilities
        searchable = json.dumps(tool).lower()
        has_dangerous = any(
            any(kw.lower() in searchable for kw in cap.get("keywords", []))
            for cap in self._caps.values()
        )

        if has_dangerous and not has_auth:
            self.findings.append(Finding.agent_mcp(
                rule_id="MCP-050",
                title="Dangerous tool without auth requirements",
                description=f"Tool '{name}' has dangerous capabilities but no authentication/"
                            "authorization metadata. "
                            "Add 'requiresConfirmation', 'permissions', or 'auth' fields.",
                severity=Severity.HIGH,
                target=source,
                evidence=f"tool={name}",
            ))

    def _check_input_validation(self, tool: dict, name: str, source: str) -> None:
        """Check for path traversal and injection risks (YAML-driven keywords)."""
        schema = tool.get("inputSchema", tool.get("parameters", {}))
        properties = schema.get("properties", {}) if schema else {}

        path_params = [
            k for k in properties.keys()
            if any(w in k.lower() for w in self._path_keywords)
        ]

        for param in path_params:
            prop_def = properties[param]
            has_path_protection = any(k in prop_def for k in ["pattern", "enum", "const"])

            if not has_path_protection:
                self.findings.append(Finding.agent_mcp(
                    rule_id="MCP-060",
                    title=f"Path parameter without validation: {param}",
                    description=f"Tool '{name}' parameter '{param}' accepts file paths/URLs "
                                "without pattern validation. "
                                "This is vulnerable to path traversal (e.g., '../../etc/passwd').",
                    severity=Severity.HIGH,
                    target=source,
                    evidence=f"tool={name}, param={param}, validation=none",
                ))

    def _check_schema_depth(self, tool: dict, name: str, source: str) -> None:
        """Check for deeply nested schemas that could cause DoS."""
        schema = tool.get("inputSchema", tool.get("parameters", {}))
        if not schema:
            return

        depth = self._measure_depth(schema)
        if depth > 10:
            self.findings.append(Finding.agent_mcp(
                rule_id="MCP-070",
                title="Excessively deep schema nesting",
                description=f"Tool '{name}' has schema nesting depth of {depth}. "
                            "Deeply nested schemas can cause parsing DoS.",
                severity=Severity.MEDIUM,
                target=source,
                evidence=f"tool={name}, depth={depth}",
            ))

    @staticmethod
    def _measure_depth(obj: Any, current: int = 0) -> int:
        """Measure maximum nesting depth of a JSON structure."""
        if isinstance(obj, dict):
            if not obj:
                return current
            return max(MCPValidator._measure_depth(v, current + 1) for v in obj.values())
        elif isinstance(obj, list):
            if not obj:
                return current
            return max(MCPValidator._measure_depth(v, current + 1) for v in obj)
        return current
