"""Detect agent frameworks and ReAct-style tool loops."""
from __future__ import annotations

import re
from pathlib import Path

from sentinel.aibom.models import AIComponent, AIComponentType
from sentinel.aibom.scanners.base import BaseAIBOMScanner

_FRAMEWORKS = {
    "langchain": AIComponentType.AGENT,
    "langgraph": AIComponentType.AGENT_PLANNER,
    "crewai": AIComponentType.AGENT,
    "autogen": AIComponentType.AGENT,
    "smolagents": AIComponentType.AGENT,
    "agno": AIComponentType.AGENT,
    "pydantic_ai": AIComponentType.AGENT,
    "openai.beta.assistants": AIComponentType.AGENT,
    "react": AIComponentType.AGENT_REACT,
}


class AgentDetector(BaseAIBOMScanner):
    name = "agent-detector"

    def scan(self, root: Path) -> list[AIComponent]:
        out: list[AIComponent] = []
        for p in self._iter_files(root, suffixes=(".py",)):
            text = self._read(p)
            for key, kind in _FRAMEWORKS.items():
                if re.search(rf"\b{re.escape(key)}\b", text, re.IGNORECASE):
                    out.append(AIComponent(
                        type=kind,
                        name=key.split(".")[0],
                        path=str(p),
                        description=f"Agent framework usage: {key}",
                        evidence=[key],
                    ))
        return out
