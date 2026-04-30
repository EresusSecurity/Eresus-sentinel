"""Scan policy engine for AI skill scanning.

Defines presets (default, strict, permissive, custom) that control
severity thresholds, suppression rules, and action decisions.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum


class PolicyPreset(str, Enum):
    DEFAULT = "default"
    STRICT = "strict"
    PERMISSIVE = "permissive"
    CUSTOM = "custom"


class PolicyAction(str, Enum):
    BLOCK = "block"
    WARN = "warn"
    ALLOW = "allow"


@dataclass
class SeverityThreshold:
    block_at: str = "HIGH"
    warn_at: str = "MEDIUM"

    _ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]

    def action_for(self, severity: str) -> PolicyAction:
        sev_upper = severity.upper()
        block_idx = self._ORDER.index(self.block_at) if self.block_at in self._ORDER else 1
        warn_idx = self._ORDER.index(self.warn_at) if self.warn_at in self._ORDER else 2
        sev_idx = self._ORDER.index(sev_upper) if sev_upper in self._ORDER else 4

        if sev_idx <= block_idx:
            return PolicyAction.BLOCK
        if sev_idx <= warn_idx:
            return PolicyAction.WARN
        return PolicyAction.ALLOW


@dataclass
class ScanPolicy:
    """Scan policy configuration.

    Attributes:
        preset: Named preset (default/strict/permissive/custom).
        threshold: Severity thresholds for block/warn.
        suppressed_rule_ids: Rule IDs whose findings should be ignored.
        suppressed_tools: Tool names to skip entirely.
        max_risk_score: Risk score above which findings are blocked.
        require_descriptions: Fail if tools lack descriptions.
        require_auth: Fail if tools requiring auth have none.
        enable_behavioral: Run behavioral alignment analysis.
        enable_virustotal: Run VirusTotal hash lookup.
    """

    preset: PolicyPreset = PolicyPreset.DEFAULT
    threshold: SeverityThreshold = field(default_factory=SeverityThreshold)
    suppressed_rule_ids: list[str] = field(default_factory=list)
    suppressed_tools: list[str] = field(default_factory=list)
    max_risk_score: float = 0.7
    require_descriptions: bool = False
    require_auth: bool = False
    enable_behavioral: bool = False
    enable_virustotal: bool = False

    def is_suppressed(self, rule_id: str, tool_name: str = "") -> bool:
        if rule_id in self.suppressed_rule_ids:
            return True
        if tool_name and tool_name in self.suppressed_tools:
            return True
        return False

    def action_for_severity(self, severity: str) -> PolicyAction:
        return self.threshold.action_for(severity)

    @classmethod
    def default(cls) -> "ScanPolicy":
        return cls(
            preset=PolicyPreset.DEFAULT,
            threshold=SeverityThreshold(block_at="HIGH", warn_at="MEDIUM"),
            max_risk_score=0.7,
        )

    @classmethod
    def strict(cls) -> "ScanPolicy":
        return cls(
            preset=PolicyPreset.STRICT,
            threshold=SeverityThreshold(block_at="MEDIUM", warn_at="LOW"),
            max_risk_score=0.4,
            require_descriptions=True,
            require_auth=True,
            enable_behavioral=True,
        )

    @classmethod
    def permissive(cls) -> "ScanPolicy":
        return cls(
            preset=PolicyPreset.PERMISSIVE,
            threshold=SeverityThreshold(block_at="CRITICAL", warn_at="HIGH"),
            max_risk_score=0.9,
        )

    @classmethod
    def from_preset(cls, preset: str) -> "ScanPolicy":
        mapping = {
            "default": cls.default,
            "strict": cls.strict,
            "permissive": cls.permissive,
        }
        factory = mapping.get(preset.lower())
        if factory is None:
            raise ValueError(
                f"Unknown preset {preset!r}. Choose from: {list(mapping)}"
            )
        return factory()

    @classmethod
    def from_dict(cls, data: dict) -> "ScanPolicy":
        preset_str = data.get("preset", "custom")
        try:
            preset = PolicyPreset(preset_str)
        except ValueError:
            preset = PolicyPreset.CUSTOM

        threshold_data = data.get("threshold", {})
        threshold = SeverityThreshold(
            block_at=threshold_data.get("block_at", "HIGH"),
            warn_at=threshold_data.get("warn_at", "MEDIUM"),
        )
        return cls(
            preset=preset,
            threshold=threshold,
            suppressed_rule_ids=list(data.get("suppressed_rule_ids", [])),
            suppressed_tools=list(data.get("suppressed_tools", [])),
            max_risk_score=float(data.get("max_risk_score", 0.7)),
            require_descriptions=bool(data.get("require_descriptions", False)),
            require_auth=bool(data.get("require_auth", False)),
            enable_behavioral=bool(data.get("enable_behavioral", False)),
            enable_virustotal=bool(data.get("enable_virustotal", False)),
        )
