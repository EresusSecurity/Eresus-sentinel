"""Detect AI skill files (SKILL.md, AGENTS.md, .cursorrules, etc.) in the BOM."""
from __future__ import annotations

import re
from pathlib import Path

from sentinel.aibom.models import AIComponent, AIComponentType
from sentinel.aibom.scanners.base import BaseAIBOMScanner

_SKILL_FILE_NAMES = frozenset({
    "SKILL.md", "AGENTS.md", "CLAUDE.md", ".cursorrules", ".windsurfrules",
    ".github/copilot-instructions.md", "copilot-instructions.md",
})

_SKILL_FRONTMATTER_RE = re.compile(r"^---\s*\n.*?description:\s*(.+)", re.DOTALL)
_TOOL_USE_RE = re.compile(r"(?:tools?|function)[\s:]+\[([^\]]+)\]", re.IGNORECASE)


class SkillDetector(BaseAIBOMScanner):
    name = "skill-detector"

    def scan(self, root: Path) -> list[AIComponent]:
        out: list[AIComponent] = []
        for p in self._iter_files(root):
            if p.name in _SKILL_FILE_NAMES or any(
                str(p).endswith(n) for n in _SKILL_FILE_NAMES if "/" in n
            ):
                self._analyze_skill(p, out)
        for p in self._iter_files(root, suffixes=(".md",)):
            if p.name.startswith("SKILL") or "skill" in p.name.lower():
                text = self._read(p)
                if "description:" in text[:500]:
                    self._analyze_skill(p, out)
        return out

    def _analyze_skill(self, p: Path, out: list[AIComponent]) -> None:
        text = self._read(p)
        description = ""
        m = _SKILL_FRONTMATTER_RE.search(text[:1000])
        if m:
            description = m.group(1).strip()[:200]

        tools: list[str] = []
        tm = _TOOL_USE_RE.search(text)
        if tm:
            tools = [t.strip().strip("\"'") for t in tm.group(1).split(",")]

        out.append(AIComponent(
            type=AIComponentType.SKILL,
            name=p.name,
            path=str(p),
            description=description or f"AI skill file: {p.name}",
            evidence=["skill-file"],
            properties={
                "skill_type": self._classify_skill_type(p.name),
                "has_frontmatter": "---" in text[:10],
                "tool_count": len(tools),
                "tools": tools[:20],
                "size_bytes": len(text),
            },
        ))

    @staticmethod
    def _classify_skill_type(name: str) -> str:
        mapping = {
            "SKILL.md": "agent-skill",
            "AGENTS.md": "agent-instructions",
            "CLAUDE.md": "claude-instructions",
            ".cursorrules": "cursor-rules",
            ".windsurfrules": "windsurf-rules",
            "copilot-instructions.md": "copilot-instructions",
        }
        return mapping.get(name, "skill-file")
