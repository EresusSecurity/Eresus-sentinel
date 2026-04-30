"""Resolve remote agent references (URLs, registry IDs) into BOM components."""
from __future__ import annotations

import re
from pathlib import Path

from sentinel.aibom.models import AIComponent, AIComponentType
from sentinel.aibom.scanners.base import BaseAIBOMScanner

_REMOTE_AGENT_PATTERNS = [
    (re.compile(r"""(?:agent_url|remote_agent|agent_endpoint)\s*[:=]\s*["']([^"']+)["']"""), "agent-url"),
    (re.compile(r"""https?://[^\s"']+/\.well-known/agent\.json"""), "well-known-url"),
    (re.compile(r"""A2ACardResolver\s*\(\s*["']([^"']+)["']"""), "a2a-resolver"),
    (re.compile(r"""fetch_agent_card\s*\(\s*["']([^"']+)["']"""), "fetch-agent-card"),
]


class RemoteAgentResolver(BaseAIBOMScanner):
    name = "remote-agent-resolver"

    def scan(self, root: Path) -> list[AIComponent]:
        out: list[AIComponent] = []
        seen: set[str] = set()
        for p in self._iter_files(root, suffixes=(".py", ".yaml", ".yml", ".json", ".toml")):
            text = self._read(p)
            for rx, source in _REMOTE_AGENT_PATTERNS:
                for m in rx.finditer(text):
                    url = m.group(1) if m.lastindex else m.group(0)
                    if url in seen:
                        continue
                    seen.add(url)
                    line_no = text[:m.start()].count("\n") + 1
                    out.append(AIComponent(
                        type=AIComponentType.AGENT,
                        name=f"remote-agent:{url[:80]}",
                        path=str(p),
                        description=f"Remote agent reference ({source})",
                        evidence=[source],
                        properties={"url": url, "detection": source, "line": line_no},
                    ))
        return out
