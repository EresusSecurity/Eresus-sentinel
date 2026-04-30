"""YARA mode enum and policy matrix for skill scanning."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class YaraMode(str, Enum):
    OFF = "off"
    DETECT = "detect"
    ENFORCE = "enforce"
    AUDIT = "audit"


@dataclass
class YaraPolicyEntry:
    rule_name: str
    mode: YaraMode
    severity_override: str | None = None
    metadata: dict[str, Any] = field(default_factory=dict)


class YaraPolicyMatrix:
    """Policy matrix mapping YARA rules to modes."""

    def __init__(self) -> None:
        self._entries: dict[str, YaraPolicyEntry] = {}
        self._default_mode = YaraMode.DETECT

    def set_default(self, mode: YaraMode) -> None:
        self._default_mode = mode

    def set(self, rule_name: str, mode: YaraMode, severity_override: str | None = None) -> None:
        self._entries[rule_name] = YaraPolicyEntry(rule_name, mode, severity_override)

    def get_mode(self, rule_name: str) -> YaraMode:
        entry = self._entries.get(rule_name)
        return entry.mode if entry else self._default_mode

    def is_enforced(self, rule_name: str) -> bool:
        return self.get_mode(rule_name) == YaraMode.ENFORCE

    def is_active(self, rule_name: str) -> bool:
        return self.get_mode(rule_name) != YaraMode.OFF

    def load_from_dict(self, data: dict[str, Any]) -> None:
        default = data.get("default_mode", "detect")
        self._default_mode = YaraMode(default)
        for name, config in data.get("rules", {}).items():
            if isinstance(config, str):
                self.set(name, YaraMode(config))
            elif isinstance(config, dict):
                self.set(name, YaraMode(config.get("mode", "detect")),
                         config.get("severity_override"))

    @property
    def entry_count(self) -> int:
        return len(self._entries)

    @property
    def default_mode(self) -> YaraMode:
        return self._default_mode
