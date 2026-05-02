"""MCP server scorecard for quick trust review."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

SCORECARD_SCHEMA_VERSION = "mcp.scorecard.v1"


@dataclass
class MCPScorecard:
    score: int
    grade: str
    risks: list[str] = field(default_factory=list)
    schema_version: str = SCORECARD_SCHEMA_VERSION

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": self.schema_version,
            "score": self.score,
            "grade": self.grade,
            "risks": self.risks,
        }


def score_mcp_manifest(manifest: dict[str, Any]) -> MCPScorecard:
    """Score a manifest using deterministic structural signals."""
    score = 100
    risks: list[str] = []

    tools = manifest.get("tools", [])
    if isinstance(tools, list):
        dangerous_names = [
            str(tool.get("name", ""))
            for tool in tools
            if isinstance(tool, dict)
            and any(token in str(tool.get("name", "")).lower() for token in ("exec", "shell", "write", "delete"))
        ]
        if dangerous_names:
            risks.append(f"dangerous-tool-names:{','.join(dangerous_names[:5])}")
            score -= min(35, 10 * len(dangerous_names))
        if len(tools) > 25:
            risks.append("large-tool-surface")
            score -= 10

    auth = manifest.get("auth") or manifest.get("authentication")
    if not auth:
        risks.append("missing-auth-metadata")
        score -= 20

    resources = manifest.get("resources", [])
    if isinstance(resources, list):
        risky_resources = [
            str(item.get("uri", item.get("url", "")))
            for item in resources
            if isinstance(item, dict)
            and str(item.get("uri", item.get("url", ""))).startswith(("file://", "http://169.254."))
        ]
        if risky_resources:
            risks.append("risky-resource-uri")
            score -= 20

    instructions = str(manifest.get("instructions", ""))
    if any(token in instructions.lower() for token in ("ignore previous", "system prompt", "developer message")):
        risks.append("instruction-injection-language")
        score -= 25

    score = max(0, min(100, score))
    if score >= 90:
        grade = "A"
    elif score >= 75:
        grade = "B"
    elif score >= 60:
        grade = "C"
    elif score >= 40:
        grade = "D"
    else:
        grade = "F"
    return MCPScorecard(score=score, grade=grade, risks=risks)
