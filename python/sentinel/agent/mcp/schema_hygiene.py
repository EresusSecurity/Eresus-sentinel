"""Schema-hygiene analyzer.

Detects overly permissive JSON-schema definitions on MCP tool input:
``additionalProperties: true``, missing ``required``, unconstrained
strings, typeless properties, unstructured objects, arrays without
``items``, and excessive nesting depth.
"""

from __future__ import annotations

from typing import Any

from ...finding import Finding, Severity

_STRING_CONSTRAINT_KEYS = ("maxLength", "pattern", "enum", "const", "format", "minLength")
_PATH_PROP_CONSTRAINT_KEYS = ("pattern", "enum", "const")
_MAX_NESTING_DEPTH = 10


def check_required_fields(
    tool: dict[str, Any],
    tool_name: str,
    source: str,
    findings: list[Finding],
) -> None:
    """Flag MCP tools missing the ``name``, ``description``, or
    ``inputSchema``/``parameters`` fields.
    """
    for field in ("name", "description"):
        if not tool.get(field):
            findings.append(Finding.agent_mcp(
                rule_id="MCP-010",
                title=f"Missing required field: {field}",
                description=(
                    f"Tool '{tool_name}' is missing required field "
                    f"'{field}'. All MCP tools must declare name and "
                    "description."
                ),
                severity=Severity.MEDIUM,
                target=source,
                evidence=f"tool={tool_name}, missing={field}",
            ))

    if "inputSchema" not in tool and "parameters" not in tool:
        findings.append(Finding.agent_mcp(
            rule_id="MCP-011",
            title="Missing input schema",
            description=(
                f"Tool '{tool_name}' has no inputSchema or parameters "
                "definition. This allows arbitrary input."
            ),
            severity=Severity.HIGH,
            target=source,
            evidence=f"tool={tool_name}",
        ))


def check_schema_permissiveness(
    tool: dict[str, Any],
    tool_name: str,
    source: str,
    findings: list[Finding],
) -> None:
    """Report permissive schema patterns on the tool's input schema."""
    schema = tool.get("inputSchema", tool.get("parameters", {}))
    if not schema:
        return

    if schema.get("additionalProperties", False) is True:
        findings.append(Finding.agent_mcp(
            rule_id="MCP-030",
            title="Overly permissive schema (additionalProperties: true)",
            description=(
                f"Tool '{tool_name}' allows arbitrary additional "
                "properties in input. This can be exploited to inject "
                "unexpected parameters."
            ),
            severity=Severity.HIGH,
            target=source,
            evidence=f"tool={tool_name}, additionalProperties=true",
        ))

    if "required" not in schema and schema.get("properties"):
        findings.append(Finding.agent_mcp(
            rule_id="MCP-033",
            title="No required fields defined in schema",
            description=(
                f"Tool '{tool_name}' schema has properties but no "
                "'required' field. All critical parameters should be "
                "required."
            ),
            severity=Severity.MEDIUM,
            target=source,
            evidence=f"tool={tool_name}, required=undefined",
        ))

    properties = schema.get("properties", {})
    for prop_name, prop_def in properties.items():
        _check_property(prop_def, prop_name, tool_name, source, findings)


def _check_property(
    prop_def: dict[str, Any],
    prop_name: str,
    tool_name: str,
    source: str,
    findings: list[Finding],
) -> None:
    prop_type = prop_def.get("type", "")

    if not prop_type:
        findings.append(Finding.agent_mcp(
            rule_id="MCP-034",
            title=f"Typeless property: {prop_name}",
            description=(
                f"Tool '{tool_name}' property '{prop_name}' has no type "
                "defined. This accepts any value."
            ),
            severity=Severity.HIGH,
            target=source,
            evidence=f"tool={tool_name}, property={prop_name}, type=undefined",
        ))
        return

    if prop_type == "string":
        has_constraint = any(k in prop_def for k in _STRING_CONSTRAINT_KEYS)
        if not has_constraint:
            findings.append(Finding.agent_mcp(
                rule_id="MCP-031",
                title=f"Unconstrained string input: {prop_name}",
                description=(
                    f"Tool '{tool_name}' property '{prop_name}' is a "
                    "string with no length, pattern, or enum "
                    "constraint. Consider adding maxLength or pattern "
                    "validation."
                ),
                severity=Severity.LOW,
                target=source,
                evidence=(
                    f"tool={tool_name}, property={prop_name}, "
                    "type=string, constraints=none"
                ),
            ))
    elif prop_type == "object" and "properties" not in prop_def:
        findings.append(Finding.agent_mcp(
            rule_id="MCP-032",
            title=f"Unstructured object input: {prop_name}",
            description=(
                f"Tool '{tool_name}' property '{prop_name}' accepts "
                "arbitrary objects with no defined schema."
            ),
            severity=Severity.MEDIUM,
            target=source,
            evidence=(
                f"tool={tool_name}, property={prop_name}, type=object, "
                "properties=undefined"
            ),
        ))
    elif prop_type == "array" and "items" not in prop_def:
        findings.append(Finding.agent_mcp(
            rule_id="MCP-035",
            title=f"Array without items schema: {prop_name}",
            description=(
                f"Tool '{tool_name}' property '{prop_name}' is an "
                "array with no items schema."
            ),
            severity=Severity.MEDIUM,
            target=source,
            evidence=(
                f"tool={tool_name}, property={prop_name}, type=array, "
                "items=undefined"
            ),
        ))


def check_schema_depth(
    tool: dict[str, Any],
    tool_name: str,
    source: str,
    findings: list[Finding],
) -> None:
    """Emit ``MCP-070`` when schema nesting exceeds ``_MAX_NESTING_DEPTH``."""
    schema = tool.get("inputSchema", tool.get("parameters", {}))
    if not schema:
        return

    depth = _measure_depth(schema)
    if depth > _MAX_NESTING_DEPTH:
        findings.append(Finding.agent_mcp(
            rule_id="MCP-070",
            title="Excessively deep schema nesting",
            description=(
                f"Tool '{tool_name}' has schema nesting depth of "
                f"{depth}. Deeply nested schemas can cause parsing DoS."
            ),
            severity=Severity.MEDIUM,
            target=source,
            evidence=f"tool={tool_name}, depth={depth}",
        ))


def check_path_parameter_validation(
    tool: dict[str, Any],
    tool_name: str,
    source: str,
    path_keywords: list[str],
    findings: list[Finding],
) -> None:
    """Flag path/url-named parameters with no pattern/enum constraint."""
    schema = tool.get("inputSchema", tool.get("parameters", {}))
    properties = schema.get("properties", {}) if schema else {}

    path_params = [
        k for k in properties
        if any(w in k.lower() for w in path_keywords)
    ]

    for param in path_params:
        prop_def = properties[param]
        if any(k in prop_def for k in _PATH_PROP_CONSTRAINT_KEYS):
            continue
        findings.append(Finding.agent_mcp(
            rule_id="MCP-060",
            title=f"Path parameter without validation: {param}",
            description=(
                f"Tool '{tool_name}' parameter '{param}' accepts file "
                "paths/URLs without pattern validation. This is "
                "vulnerable to path traversal (e.g., '../../etc/passwd')."
            ),
            severity=Severity.HIGH,
            target=source,
            evidence=f"tool={tool_name}, param={param}, validation=none",
        ))


def _measure_depth(obj: Any, current: int = 0) -> int:
    if isinstance(obj, dict):
        if not obj:
            return current
        return max(_measure_depth(v, current + 1) for v in obj.values())
    if isinstance(obj, list):
        if not obj:
            return current
        return max(_measure_depth(v, current + 1) for v in obj)
    return current
