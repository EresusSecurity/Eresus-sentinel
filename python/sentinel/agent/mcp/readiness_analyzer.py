"""MCP Server Readiness Analyzer.

Scores an MCP server's production-readiness across five dimensions:
  auth         — authentication/authorization present
  schema       — input schemas well-defined
  error_handling — error responses documented
  documentation — tool descriptions complete
  security     — no obvious security issues

Produces a 0–100 readiness score with per-dimension breakdown.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any


@dataclass
class DimensionScore:
    name: str
    score: float
    max_score: float
    notes: list[str] = field(default_factory=list)

    @property
    def percentage(self) -> float:
        return (self.score / self.max_score * 100) if self.max_score else 0.0


@dataclass
class ReadinessResult:
    server_name: str
    total_score: float
    max_score: float
    dimensions: list[DimensionScore] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)

    @property
    def percentage(self) -> float:
        return (self.total_score / self.max_score * 100) if self.max_score else 0.0

    @property
    def grade(self) -> str:
        p = self.percentage
        if p >= 90:
            return "A"
        if p >= 75:
            return "B"
        if p >= 60:
            return "C"
        if p >= 40:
            return "D"
        return "F"


class ReadinessAnalyzer:
    """Score an MCP server manifest for production readiness.

    Args:
        server_info: Top-level server info dict (``name``, ``version``, etc.)
        tools: List of tool definition dicts from the MCP manifest.
    """

    def analyze(
        self,
        server_info: dict[str, Any],
        tools: list[dict[str, Any]],
        capabilities: dict[str, Any] | None = None,
    ) -> ReadinessResult:
        capabilities = capabilities or {}
        server_name = server_info.get("name", "<unnamed>")
        dimensions: list[DimensionScore] = []

        dimensions.append(self._score_auth(server_info, capabilities))
        dimensions.append(self._score_schema(tools))
        dimensions.append(self._score_error_handling(tools))
        dimensions.append(self._score_documentation(server_info, tools))
        dimensions.append(self._score_security(server_info, tools))

        total = sum(d.score for d in dimensions)
        maximum = sum(d.max_score for d in dimensions)

        recs: list[str] = []
        for dim in dimensions:
            recs.extend(dim.notes)

        return ReadinessResult(
            server_name=server_name,
            total_score=total,
            max_score=maximum,
            dimensions=dimensions,
            recommendations=recs,
        )

    def _score_auth(
        self, server_info: dict[str, Any], capabilities: dict[str, Any]
    ) -> DimensionScore:
        score = 0.0
        notes: list[str] = []

        auth_cap = capabilities.get("auth", capabilities.get("authorization", {}))
        if auth_cap:
            score += 10.0
        else:
            notes.append("No auth capabilities declared; consider adding OAuth2 or API-key auth.")

        if server_info.get("version"):
            score += 5.0

        return DimensionScore("auth", score, 15.0, notes)

    def _score_schema(self, tools: list[dict[str, Any]]) -> DimensionScore:
        if not tools:
            return DimensionScore("schema", 0.0, 20.0, ["No tools defined."])

        score = 0.0
        notes: list[str] = []
        per_tool = 20.0 / len(tools)

        for tool in tools:
            schema = tool.get("inputSchema", {})
            properties = schema.get("properties", {})
            required = schema.get("required", [])

            if properties:
                score += per_tool * 0.5
            else:
                notes.append(
                    f"Tool '{tool.get('name', '?')}' has no input schema properties."
                )
            if required:
                score += per_tool * 0.3
            if schema.get("additionalProperties") is False:
                score += per_tool * 0.2

        return DimensionScore("schema", min(score, 20.0), 20.0, notes)

    def _score_error_handling(self, tools: list[dict[str, Any]]) -> DimensionScore:
        score = 0.0
        notes: list[str] = []

        for tool in tools:
            annotations = tool.get("annotations", {})
            if annotations.get("errors") or annotations.get("errorHandling"):
                score += 5.0
                break

        if not tools:
            notes.append("No tools to evaluate for error handling.")
        elif score == 0.0:
            notes.append(
                "No tools document error responses; add 'annotations.errors' to tool definitions."
            )

        return DimensionScore("error_handling", score, 10.0, notes)

    def _score_documentation(
        self, server_info: dict[str, Any], tools: list[dict[str, Any]]
    ) -> DimensionScore:
        score = 0.0
        notes: list[str] = []

        if server_info.get("description"):
            score += 5.0
        else:
            notes.append("Server has no top-level description.")

        if server_info.get("version"):
            score += 5.0
        else:
            notes.append("Server version not declared.")

        if tools:
            desc_count = sum(1 for t in tools if t.get("description", "").strip())
            ratio = desc_count / len(tools)
            score += ratio * 15.0
            if ratio < 1.0:
                notes.append(
                    f"{len(tools) - desc_count}/{len(tools)} tools lack descriptions."
                )

        return DimensionScore("documentation", min(score, 25.0), 25.0, notes)

    def _score_security(
        self, server_info: dict[str, Any], tools: list[dict[str, Any]]
    ) -> DimensionScore:
        score = 30.0
        notes: list[str] = []

        dangerous_names = {"exec", "shell", "eval", "system", "run_command"}
        for tool in tools:
            name = tool.get("name", "").lower()
            if any(d in name for d in dangerous_names):
                score -= 10.0
                notes.append(
                    f"Tool '{tool.get('name')}' has a potentially dangerous name; "
                    "verify it is intentional and properly sandboxed."
                )

            schema = tool.get("inputSchema", {})
            for prop, defn in schema.get("properties", {}).items():
                if defn.get("type") == "string" and not defn.get("pattern") and not defn.get("enum"):
                    score -= 0.5

        score = max(0.0, score)
        return DimensionScore("security", score, 30.0, notes)
