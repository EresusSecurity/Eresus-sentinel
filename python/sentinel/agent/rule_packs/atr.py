"""ATR (Agent Threat Rules) signature pack with YAML provenance."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_DEFAULT_ATR_PATH = Path(__file__).parent.parent.parent.parent / "rules" / "agent_atr_signatures.yaml"


@dataclass
class ATRSignature:
    id: str
    name: str
    description: str = ""
    severity: str = "medium"
    patterns: list[str] = field(default_factory=list)
    tags: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


class ATRPack:
    """ATR signature pack loader and matcher."""

    def __init__(self) -> None:
        self._signatures: list[ATRSignature] = []

    def load_yaml(self, path: Path | None = None) -> int:
        target = path or _DEFAULT_ATR_PATH
        if not target.exists():
            logger.debug("ATR signatures file not found: %s", target)
            return 0
        try:
            data = yaml.safe_load(target.read_text(encoding="utf-8"))
        except Exception as e:
            logger.warning("Failed to load ATR pack: %s", e)
            return 0
        if not isinstance(data, dict):
            return 0
        sigs = data.get("signatures", [])
        for s in sigs:
            if isinstance(s, dict) and "id" in s:
                self._signatures.append(ATRSignature(
                    id=s["id"],
                    name=s.get("name", s["id"]),
                    description=s.get("description", ""),
                    severity=s.get("severity", "medium"),
                    patterns=s.get("patterns", []),
                    tags=s.get("tags", []),
                    metadata=s.get("metadata", {}),
                ))
        return len(sigs)

    def load_builtins(self) -> int:
        self._signatures.extend([
            ATRSignature("ATR-001", "Prompt injection attempt",
                         "Detects prompt injection patterns in skill files",
                         "high", [r"ignore\s+(?:all\s+)?(?:previous|above)\s+instructions"]),
            ATRSignature("ATR-002", "System prompt extraction",
                         "Detects system prompt leak attempts",
                         "high", [r"(?:print|repeat|show)\s+(?:your|the)\s+(?:system|initial)\s+(?:prompt|instructions)"]),
            ATRSignature("ATR-003", "Tool abuse pattern",
                         "Detects tool misuse patterns",
                         "medium", [r"(?:execute|run)\s+(?:arbitrary|any)\s+(?:command|code)"]),
            ATRSignature("ATR-004", "Data exfiltration attempt",
                         "Detects data exfil patterns",
                         "critical", [r"(?:send|upload|post)\s+(?:all|every)\s+(?:file|data|content)"]),
        ])
        return len(self._signatures)

    @property
    def signature_count(self) -> int:
        return len(self._signatures)

    def all_signatures(self) -> list[ATRSignature]:
        return list(self._signatures)
