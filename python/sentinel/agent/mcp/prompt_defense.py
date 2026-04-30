"""Prompt defense evaluator for MCP servers.

Evaluates whether an MCP server's tool descriptions and schema are robust
against prompt injection attacks — i.e. whether an adversarial MCP server
could manipulate the calling LLM through crafted description text.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any

from .negation import NEGATION_PATTERN, _WINDOW_CHARS

_INJECTION_PATTERNS = [
    re.compile(r"ignore\s+(?:all\s+)?(?:instructions?|rules?|system\s+prompt)", re.IGNORECASE),
    re.compile(r"ignore\s+(?:\w+\s+)*(previous|prior|above|all\s+previous)\s+(instructions?|prompt)", re.IGNORECASE),
    re.compile(r"disregard\s+(?:\w+\s+)*(?:instructions?|system\s+prompt|prompt|rules?)", re.IGNORECASE),
    re.compile(r"you\s+are\s+now\s+(?:a|an)\s+", re.IGNORECASE),
    re.compile(r"forget\s+(?:\w+\s+)*(?:instructions?|system\s+prompt|prompt|rules?)", re.IGNORECASE),
    re.compile(r"do\s+not\s+(?:follow|obey)\s+", re.IGNORECASE),
    re.compile(r"\[SYSTEM\]|\[INST\]|\[/INST\]|<\|system\|>", re.IGNORECASE),
    re.compile(r"assistant\s*:\s*sure", re.IGNORECASE),
    re.compile(r"jailbreak|DAN\b|do\s+anything\s+now", re.IGNORECASE),
    re.compile(r"<\s*script\s*>|javascript\s*:", re.IGNORECASE),
    re.compile(r"base64\s*\(|atob\s*\(", re.IGNORECASE),
    re.compile(r"reveal\s+(?:\w+\s+)*(?:system|internal|hidden)\s+(?:prompt|key|secret)", re.IGNORECASE),
    re.compile(r"output\s+(?:the\s+)?(?:system|hidden|secret|internal)\s+(?:prompt|key)", re.IGNORECASE),
    re.compile(r"override\s+(?:\w+\s+)*(?:safety|security|instructions?|rules?)", re.IGNORECASE),
    re.compile(r"pretend\s+(?:you\s+)?(?:are|have)\s+no\s+(?:restrictions?|rules?|guidelines?)", re.IGNORECASE),
]

_OVERLY_BROAD_ACCESS = [
    re.compile(r"\ball\s+files?\b", re.IGNORECASE),
    re.compile(r"unrestricted\s+access", re.IGNORECASE),
    re.compile(r"bypass\s+(?:safety|security|permission)", re.IGNORECASE),
    re.compile(r"no\s+(?:restrictions?|limits?)", re.IGNORECASE),
]


@dataclass
class DefenseIssue:
    field: str
    pattern: str
    snippet: str
    severity: str


@dataclass
class PromptDefenseResult:
    tool_name: str
    score: float
    passed: bool
    issues: list[DefenseIssue] = field(default_factory=list)
    recommendations: list[str] = field(default_factory=list)


class PromptDefenseAnalyzer:
    """Evaluate MCP tool descriptions for prompt-injection vectors.

    Args:
        passing_score: Minimum score to consider the tool safe (default 0.7).
    """

    def __init__(self, passing_score: float = 0.7) -> None:
        self._passing_score = passing_score

    def analyze_tool(self, tool: dict[str, Any]) -> PromptDefenseResult:
        """Analyze a single MCP tool definition dict.

        Expected keys: ``name``, ``description``, ``inputSchema``
        """
        name = tool.get("name", "<unnamed>")
        issues: list[DefenseIssue] = []
        recommendations: list[str] = []

        fields_to_scan: list[tuple[str, str]] = []

        desc = tool.get("description", "")
        if desc:
            fields_to_scan.append(("description", desc))

        schema = tool.get("inputSchema", {})
        for prop, prop_def in schema.get("properties", {}).items():
            prop_desc = prop_def.get("description", "")
            if prop_desc:
                fields_to_scan.append((f"inputSchema.properties.{prop}.description", prop_desc))

        for field_name, text in fields_to_scan:
            for pat in _INJECTION_PATTERNS:
                m = pat.search(text)
                if m:
                    if _is_negated_match(text, m.start()):
                        continue
                    snippet = text[max(0, m.start() - 20): m.end() + 20]
                    issues.append(DefenseIssue(
                        field=field_name,
                        pattern=pat.pattern,
                        snippet=snippet,
                        severity="HIGH",
                    ))

            for pat in _OVERLY_BROAD_ACCESS:
                m = pat.search(text)
                if m:
                    snippet = text[max(0, m.start() - 20): m.end() + 20]
                    issues.append(DefenseIssue(
                        field=field_name,
                        pattern=pat.pattern,
                        snippet=snippet,
                        severity="MEDIUM",
                    ))

        if not desc:
            recommendations.append("Add a clear, concise description to the tool.")
        elif len(desc) > 2000:
            recommendations.append(
                "Description is unusually long (>2000 chars); verify it doesn't contain injected instructions."
            )

        if not schema.get("required"):
            recommendations.append(
                "No required fields declared; add input validation to prevent schema abuse."
            )

        penalty = sum(
            0.3 if i.severity == "HIGH" else 0.1
            for i in issues
        )
        score = max(0.0, 1.0 - penalty)

        return PromptDefenseResult(
            tool_name=name,
            score=score,
            passed=score >= self._passing_score and not any(
                i.severity == "HIGH" for i in issues
            ),
            issues=issues,
            recommendations=recommendations,
        )

    def analyze_server(self, tools: list[dict[str, Any]]) -> list[PromptDefenseResult]:
        """Analyze all tools in an MCP server manifest."""
        return [self.analyze_tool(t) for t in tools]


def _is_negated_match(text: str, pos: int) -> bool:
    window = text.lower()[max(0, pos - _WINDOW_CHARS):pos]
    return bool(NEGATION_PATTERN.search(window))
