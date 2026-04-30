"""Cross-skill dependency graph and conflict detection."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from sentinel.finding import Finding, Severity


@dataclass
class SkillNode:
    name: str
    path: str
    tools: list[str] = field(default_factory=list)
    dependencies: list[str] = field(default_factory=list)
    permissions: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class SkillConflict:
    skill_a: str
    skill_b: str
    conflict_type: str  # "tool_overlap", "permission_escalation", "circular_dep"
    details: str = ""


class CrossSkillScanner:
    """Analyze cross-skill dependencies and detect conflicts."""

    def __init__(self) -> None:
        self._nodes: dict[str, SkillNode] = {}

    def add_skill(self, node: SkillNode) -> None:
        self._nodes[node.name] = node

    def scan_directory(self, root: Path) -> list[SkillNode]:
        nodes: list[SkillNode] = []
        for p in root.rglob("SKILL.md"):
            node = self._parse_skill(p)
            if node:
                self.add_skill(node)
                nodes.append(node)
        for p in root.rglob("AGENTS.md"):
            node = self._parse_skill(p)
            if node:
                self.add_skill(node)
                nodes.append(node)
        return nodes

    def detect_conflicts(self) -> list[SkillConflict]:
        conflicts: list[SkillConflict] = []
        names = list(self._nodes.keys())
        for i, name_a in enumerate(names):
            for name_b in names[i + 1:]:
                a, b = self._nodes[name_a], self._nodes[name_b]
                overlap = set(a.tools) & set(b.tools)
                if overlap:
                    conflicts.append(SkillConflict(
                        name_a, name_b, "tool_overlap",
                        f"Shared tools: {', '.join(overlap)}",
                    ))
        for name, node in self._nodes.items():
            for dep in node.dependencies:
                dep_node = self._nodes.get(dep)
                if dep_node and name in dep_node.dependencies:
                    conflicts.append(SkillConflict(
                        name, dep, "circular_dep",
                        f"Circular dependency: {name} <-> {dep}",
                    ))
        return conflicts

    def to_findings(self) -> list[Finding]:
        findings: list[Finding] = []
        for conflict in self.detect_conflicts():
            findings.append(Finding.agent_mcp(
                rule_id="SKILL-CROSS-001",
                title="Cross-skill conflict",
                description=f"Cross-skill conflict ({conflict.conflict_type}): {conflict.details}",
                severity=Severity.MEDIUM if conflict.conflict_type == "tool_overlap" else Severity.HIGH,
                confidence=0.8,
                target=self._nodes.get(conflict.skill_a, SkillNode("", "")).path,
            ))
        return findings

    @staticmethod
    def _parse_skill(path: Path) -> SkillNode | None:
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return None
        tools: list[str] = []
        tm = re.search(r"tools?:\s*\[([^\]]+)\]", text, re.IGNORECASE)
        if tm:
            tools = [t.strip().strip("\"'") for t in tm.group(1).split(",")]
        return SkillNode(name=path.parent.name or path.stem, path=str(path), tools=tools)

    @property
    def skill_count(self) -> int:
        return len(self._nodes)
