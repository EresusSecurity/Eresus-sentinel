"""Detect AI framework configuration files."""
from __future__ import annotations

from pathlib import Path

from sentinel.aibom.models import AIComponent, AIComponentType
from sentinel.aibom.scanners.base import BaseAIBOMScanner

_CONFIG_NAMES = {
    "langchain.yaml", "langgraph.json", "mcp.json", "claude_desktop_config.json",
    "promptfoo.yaml", "promptfoo.yml", "sentinel.toml", "dspy.yaml",
    "litellm.yaml", "litellm.yml",
}


class ConfigScanner(BaseAIBOMScanner):
    name = "config-scanner"

    def scan(self, root: Path) -> list[AIComponent]:
        out: list[AIComponent] = []
        for p in self._iter_files(root):
            if p.name in _CONFIG_NAMES:
                out.append(AIComponent(
                    type=AIComponentType.CONFIG,
                    name=p.name,
                    path=str(p),
                    description="AI framework configuration file",
                    evidence=[p.name],
                ))
        return out
