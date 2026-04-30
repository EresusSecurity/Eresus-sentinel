"""Detect MCP servers/clients and tool definitions."""
from __future__ import annotations

import json
import re
from pathlib import Path

from sentinel.aibom.models import AIComponent, AIComponentType
from sentinel.aibom.scanners.base import BaseAIBOMScanner

_MCP_IMPORT_RE = re.compile(r"\b(from|import)\s+mcp\b|modelcontextprotocol", re.IGNORECASE)


class MCPDetector(BaseAIBOMScanner):
    name = "mcp-detector"

    def scan(self, root: Path) -> list[AIComponent]:
        out: list[AIComponent] = []
        for p in self._iter_files(root, names=("mcp.json", "claude_desktop_config.json")):
            try:
                data = json.loads(self._read(p) or "{}")
            except Exception:
                data = {}
            for srv_name, meta in (data.get("mcpServers", {}) or {}).items():
                out.append(AIComponent(
                    type=AIComponentType.MCP_SERVER,
                    name=srv_name,
                    path=str(p),
                    description=str(meta.get("command", ""))[:200],
                    properties={"args": meta.get("args", []), "env": list((meta.get("env") or {}).keys())},
                    evidence=[f"mcpServers.{srv_name}"],
                ))
        for p in self._iter_files(root, suffixes=(".py",)):
            text = self._read(p)
            if _MCP_IMPORT_RE.search(text):
                out.append(AIComponent(
                    type=AIComponentType.MCP_CLIENT,
                    name=p.stem,
                    path=str(p),
                    description="MCP library usage in Python source",
                    evidence=["mcp import"],
                ))
        return out
