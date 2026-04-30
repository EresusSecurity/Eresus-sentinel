"""Detect structural agent evidence: tool definitions, planner loops, memory stores."""
from __future__ import annotations

from pathlib import Path

from sentinel.aibom.models import AIComponent, AIComponentType
from sentinel.aibom.scanners.base import BaseAIBOMScanner
from sentinel.rules import load_aibom_patterns

_CATEGORY_TYPE = {
    "tool_definitions": AIComponentType.TOOL,
    "planners": AIComponentType.AGENT_PLANNER,
    "memory": AIComponentType.CACHE,
}


class StructuralAgentScanner(BaseAIBOMScanner):
    name = "structural-agent-scanner"

    def scan(self, root: Path) -> list[AIComponent]:
        rules = load_aibom_patterns()["structural_agent"]
        out: list[AIComponent] = []
        for p in self._iter_files(root, suffixes=(".py",)):
            text = self._read(p)
            if not text:
                continue
            for category, patterns in rules.items():
                ct = _CATEGORY_TYPE.get(category, AIComponentType.TOOL)
                for rx, label, *_ in patterns:
                    if rx.search(text):
                        out.append(AIComponent(
                            type=ct, name=f"agent-{category}:{label}", path=str(p),
                            description=f"Agent structural evidence: {category} ({label})",
                            evidence=[label],
                            properties={"category": category, "pattern": label},
                        ))
                        break
        return out
