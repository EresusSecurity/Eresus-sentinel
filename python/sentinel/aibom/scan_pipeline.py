"""4-stage AIBOM pipeline: scan -> cross-reference -> enrich -> assemble."""
from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable, Optional

from sentinel.aibom.models import AIBOMResult, AIComponentType, RelationshipType
from sentinel.aibom.scanners import BaseAIBOMScanner, default_scanners


@dataclass
class ScanPipelineConfig:
    scanners: list[BaseAIBOMScanner] = field(default_factory=default_scanners)
    enrichers: list[Callable[[AIBOMResult], None]] = field(default_factory=list)
    cross_ref: bool = True
    include_paths: Optional[list[str]] = None
    exclude_paths: list[str] = field(default_factory=lambda: ["__pycache__", ".git", "node_modules", ".venv", "venv"])


class ScanPipeline:
    """Orchestrate AIBOM scanners and return a merged :class:`AIBOMResult`."""

    def __init__(self, config: Optional[ScanPipelineConfig] = None) -> None:
        self.config = config or ScanPipelineConfig()

    def run(self, root: str | Path) -> AIBOMResult:
        root_path = Path(root)
        result = AIBOMResult(metadata={"root": str(root_path.resolve())})
        for scanner in self.config.scanners:
            try:
                comps = scanner.scan(root_path)
            except Exception as exc:
                result.metadata.setdefault("errors", []).append(f"{scanner.name}: {exc}")
                continue
            for c in comps:
                if self._excluded(c.path):
                    continue
                result.add(c)
        if self.config.cross_ref:
            self._cross_reference(result)
        for enricher in self.config.enrichers:
            enricher(result)
        return result

    # ------------------------------------------------------------------
    def _excluded(self, path: str) -> bool:
        if not path:
            return False
        for bad in self.config.exclude_paths:
            if f"/{bad}/" in path or path.endswith(f"/{bad}"):
                return True
        return False

    def _cross_reference(self, result: AIBOMResult) -> None:
        by_type = result.group_by_type()
        mcp_servers = by_type.get(AIComponentType.MCP_SERVER.value, [])
        mcp_clients = by_type.get(AIComponentType.MCP_CLIENT.value, [])
        for srv in mcp_servers:
            for cli in mcp_clients:
                result.relate(cli, srv, RelationshipType.CALLS)
        agents = by_type.get(AIComponentType.AGENT.value, []) + by_type.get(AIComponentType.AGENT_PLANNER.value, [])
        models = by_type.get(AIComponentType.MODEL_LLM.value, [])
        for a in agents:
            for m in models:
                result.relate(a, m, RelationshipType.USES)
        endpoints = by_type.get(AIComponentType.ENDPOINT.value, [])
        keys = by_type.get(AIComponentType.API_KEY_REF.value, [])
        for k in keys:
            for e in endpoints:
                if self._name_matches(k.name, e.name):
                    result.relate(e, k, RelationshipType.AUTHORIZED_BY)

    @staticmethod
    def _name_matches(key_name: str, endpoint_name: str) -> bool:
        return endpoint_name.lower().split("-")[0] in key_name.lower()
