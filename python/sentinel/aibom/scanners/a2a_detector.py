"""Detect A2A (Agent-to-Agent) protocol agent cards and manifests."""
from __future__ import annotations

import json
import re
from pathlib import Path

from sentinel.aibom.models import AIComponent, AIComponentType
from sentinel.aibom.scanners.base import BaseAIBOMScanner

_WELL_KNOWN_FILENAMES = frozenset({"agent.json", "agent-card.json"})
_WELL_KNOWN_SEGMENT = ".well-known"

_AGENT_CARD_SHAPE_KEYS = frozenset({
    "name", "description", "version", "skills", "capabilities",
    "supportedInterfaces", "supported_interfaces", "api",
    "securitySchemes", "security_schemes", "identity",
    "defaultInputModes", "defaultOutputModes",
})

_PY_A2A_HINTS = ("AgentCard", "A2AServer", "A2AClient", "a2a", "agent_card")


def _looks_like_agent_card(data: dict) -> bool:
    if not isinstance(data, dict) or "name" not in data:
        return False
    skills = data.get("skills")
    if isinstance(skills, list) and skills:
        first = skills[0]
        if isinstance(first, dict) and ("id" in first or "name" in first):
            return True
    caps = data.get("capabilities") or data.get("supportedInterfaces")
    if isinstance(caps, (dict, list)) and caps:
        return True
    api = data.get("api")
    if isinstance(api, dict) and str(api.get("type", "")).lower() == "a2a":
        return True
    return False


def _redact_card(data: dict) -> dict:
    safe = {}
    for k in ("name", "description", "version"):
        if isinstance(data.get(k), str):
            safe[k] = data[k]
    skills = data.get("skills")
    if isinstance(skills, list):
        safe["skill_count"] = len(skills)
    security = data.get("securitySchemes") or data.get("security_schemes")
    if isinstance(security, dict):
        safe["security_scheme_types"] = sorted({
            v.get("type", "unknown") if isinstance(v, dict) else "unknown"
            for v in security.values()
        })
    return safe


class A2ADetector(BaseAIBOMScanner):
    name = "a2a-detector"

    def scan(self, root: Path) -> list[AIComponent]:
        out: list[AIComponent] = []
        for p in self._iter_files(root, suffixes=(".json",)):
            self._scan_json(p, out)
        for p in self._iter_files(root, suffixes=(".py",)):
            self._scan_python(p, out)
        return out

    def _scan_json(self, p: Path, out: list[AIComponent]) -> None:
        try:
            if p.stat().st_size > 512_000:
                return
            data = json.loads(p.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return
        if not isinstance(data, dict):
            return
        well_known = _WELL_KNOWN_SEGMENT in p.parts and p.name in _WELL_KNOWN_FILENAMES
        if not _looks_like_agent_card(data) and not well_known:
            return
        card = _redact_card(data)
        out.append(AIComponent(
            type=AIComponentType.AGENT,
            name=card.get("name", p.stem),
            path=str(p),
            description=f"A2A Agent Card: {card.get('description', '')}".strip(),
            evidence=["a2a-agent-card-json"],
            properties={"agent_card": card, "well_known": well_known},
        ))

    def _scan_python(self, p: Path, out: list[AIComponent]) -> None:
        text = self._read(p)
        if not any(hint in text for hint in _PY_A2A_HINTS):
            return
        for pattern in (
            r"AgentCard\s*\(",
            r"A2AServer\s*\(",
            r"A2AClient\s*\(",
        ):
            for m in re.finditer(pattern, text):
                line_no = text[:m.start()].count("\n") + 1
                constructor = m.group(0).rstrip("( ")
                out.append(AIComponent(
                    type=AIComponentType.AGENT,
                    name=f"a2a-{constructor.lower()}",
                    path=str(p),
                    description=f"A2A {constructor} constructor at line {line_no}",
                    evidence=[f"a2a-python-{constructor.lower()}"],
                    properties={"constructor": constructor, "line": line_no},
                ))
