"""DefenseClaw-style admission gate for AI skills, MCP servers, and plugins.

Mirrors the DefenseClaw concept: scan every skill/MCP/plugin *before* it is
allowed to run.  The gate produces a ``GateDecision`` with an auto-action:

- ``BLOCK``  — CRITICAL or HIGH finding → component rejected
- ``WARN``   — MEDIUM or LOW finding → component installed with a warning
- ``ALLOW``  — no findings or INFO only → clean pass-through

All outcomes are structured as ``GateDecision`` dataclasses and can be stored
in the audit log.

Usage::

    from sentinel.agent.admission_gate import AdmissionGate, ComponentType

    gate = AdmissionGate()
    decision = gate.evaluate("web-search", ComponentType.SKILL, source="path/to/skill")
    if decision.blocked:
        raise RuntimeError(f"Skill blocked: {decision.reason}")
"""

from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)
GATE_DECISION_SCHEMA_VERSION = "admission.gate.v1"


class ComponentType(str, Enum):
    SKILL = "skill"
    MCP = "mcp"
    PLUGIN = "plugin"


class GateAction(str, Enum):
    BLOCK = "block"
    WARN = "warn"
    ALLOW = "allow"


@dataclass
class GateFinding:
    rule_id: str
    severity: str
    description: str
    source: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        return {
            "rule_id": self.rule_id,
            "severity": self.severity,
            "description": self.description,
            "source": self.source,
            "metadata": self.metadata,
        }


@dataclass
class GateDecision:
    component_name: str
    component_type: ComponentType
    action: GateAction
    findings: list[GateFinding] = field(default_factory=list)
    reason: str = ""
    scan_duration_ms: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def blocked(self) -> bool:
        return self.action == GateAction.BLOCK

    @property
    def warned(self) -> bool:
        return self.action == GateAction.WARN

    @property
    def allowed(self) -> bool:
        return self.action == GateAction.ALLOW

    def to_dict(self) -> dict[str, Any]:
        severity_counts: dict[str, int] = {}
        for finding in self.findings:
            severity = finding.severity.upper()
            severity_counts[severity] = severity_counts.get(severity, 0) + 1
        return {
            "schema_version": GATE_DECISION_SCHEMA_VERSION,
            "component_name": self.component_name,
            "component_type": self.component_type.value,
            "action": self.action.value,
            "reason": self.reason,
            "scan_duration_ms": round(self.scan_duration_ms, 2),
            "summary": {
                "total_findings": len(self.findings),
                "by_severity": severity_counts,
                "blocked": self.blocked,
                "warned": self.warned,
                "allowed": self.allowed,
            },
            "findings": [f.to_dict() for f in self.findings],
            "metadata": self.metadata,
        }


# Severity ordering: lower index = more severe
_SEVERITY_ORDER = ["CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"]


def _severity_rank(severity: str) -> int:
    try:
        return _SEVERITY_ORDER.index(severity.upper())
    except ValueError:
        return len(_SEVERITY_ORDER)


def _action_for_findings(findings: list[GateFinding]) -> tuple[GateAction, str]:
    """Compute the gate action from the finding list."""
    if not findings:
        return GateAction.ALLOW, "no findings"

    ordered = sorted(findings, key=lambda f: _severity_rank(f.severity))
    highest_rank = _severity_rank(ordered[0].severity)
    highest_sev = _SEVERITY_ORDER[highest_rank] if highest_rank < len(_SEVERITY_ORDER) else "INFO"

    if highest_rank <= 1:  # CRITICAL or HIGH
        return GateAction.BLOCK, f"{highest_sev} finding: {ordered[0].description[:120]}"
    if highest_rank <= 3:  # MEDIUM or LOW
        return GateAction.WARN, f"{highest_sev} finding: {ordered[0].description[:120]}"
    return GateAction.ALLOW, f"INFO-only findings ({len(findings)} total)"


class AdmissionGate:
    """Admission gate — scan a component before allowing it to execute.

    Args:
        skill_scanner: Optional override for skill scanner.
        mcp_scanner: Optional override for MCP scanner.
        enable_virustotal: Whether to run VirusTotal hash lookup.
    """

    def __init__(
        self,
        enable_virustotal: bool = False,
        vt_api_key: str = "",
    ) -> None:
        self._enable_vt = enable_virustotal
        self._vt_api_key = vt_api_key

    # ── Public API ────────────────────────────────────────────────────

    def evaluate(
        self,
        name: str,
        component_type: ComponentType,
        *,
        source: str | Path | None = None,
        metadata: Optional[dict[str, Any]] = None,
    ) -> GateDecision:
        """Scan *name* and return an admission decision.

        Args:
            name: Human-readable component name (e.g. "web-search").
            component_type: SKILL, MCP, or PLUGIN.
            source: Path to the component's files (optional).
            metadata: Extra context forwarded to scanners.
        """
        import time
        t0 = time.time()
        findings: list[GateFinding] = []

        try:
            if component_type == ComponentType.SKILL:
                findings.extend(self._scan_skill(name, source, metadata or {}))
            elif component_type == ComponentType.MCP:
                findings.extend(self._scan_mcp(name, source, metadata or {}))
            elif component_type == ComponentType.PLUGIN:
                findings.extend(self._scan_plugin(name, source, metadata or {}))
        except Exception as exc:
            logger.warning("AdmissionGate scan error for %s: %s", name, exc)
            findings.append(
                GateFinding(
                    rule_id="GATE-001",
                    severity="HIGH",
                    description=f"Scanner error during admission check: {exc}",
                    source=str(source or ""),
                )
            )

        action, reason = _action_for_findings(findings)
        duration_ms = (time.time() - t0) * 1000

        decision = GateDecision(
            component_name=name,
            component_type=component_type,
            action=action,
            findings=findings,
            reason=reason,
            scan_duration_ms=duration_ms,
            metadata=metadata or {},
        )
        self._log_decision(decision)
        return decision

    def evaluate_path(self, path: str | Path, component_type: ComponentType) -> GateDecision:
        """Convenience: scan a file/directory path."""
        p = Path(path)
        return self.evaluate(p.name, component_type, source=p)

    def evaluate_all_skills(self, skills_dir: str | Path) -> list[GateDecision]:
        """Scan every skill found in *skills_dir*."""
        root = Path(skills_dir)
        decisions: list[GateDecision] = []
        for entry in sorted(root.iterdir()):
            if entry.is_dir() or entry.suffix in {".py", ".yaml", ".yml", ".json"}:
                decisions.append(self.evaluate(entry.name, ComponentType.SKILL, source=entry))
        return decisions

    # ── Scan helpers ─────────────────────────────────────────────────

    def _scan_skill(
        self,
        name: str,
        source: str | Path | None,
        _metadata: dict[str, Any],
    ) -> list[GateFinding]:
        findings: list[GateFinding] = []
        src_path = Path(source) if source else None

        # Run skill scanner (static analysis)
        try:
            from sentinel.agent.skill_scanner import SkillScanner
            scanner = SkillScanner()
            if src_path and src_path.exists():
                raw = scanner.scan_path(str(src_path))
            else:
                raw = scanner.scan_name(name) if hasattr(scanner, "scan_name") else []
            for r in raw:
                findings.append(
                    GateFinding(
                        rule_id=getattr(r, "rule_id", "SKILL-XXX"),
                        severity=str(getattr(r, "severity", "MEDIUM")),
                        description=str(getattr(r, "description", "")),
                        source=str(src_path or ""),
                        metadata={
                            "finding_type": str(getattr(r, "finding_type", "")),
                            "location": str(getattr(r, "location", "")),
                            "category": str(getattr(r, "category", "")),
                            "evidence": str(getattr(r, "evidence", ""))[:200],
                        },
                    )
                )
        except Exception as exc:
            logger.debug("Skill scanner unavailable: %s", exc)

        # VirusTotal binary hash check
        if self._enable_vt and src_path and src_path.exists():
            findings.extend(self._vt_scan(src_path))

        return findings

    def _scan_mcp(
        self,
        name: str,
        source: str | Path | None,
        _metadata: dict[str, Any],
    ) -> list[GateFinding]:
        findings: list[GateFinding] = []
        try:
            from sentinel.agent.mcp.scanner import MCPScanner  # type: ignore[import]
            scanner = MCPScanner()
            src_path = Path(source) if source else None
            raw = scanner.scan(name=name, path=str(src_path) if src_path else None)
            for r in raw:
                findings.append(
                    GateFinding(
                        rule_id=getattr(r, "rule_id", "MCP-XXX"),
                        severity=str(getattr(r, "severity", "MEDIUM")),
                        description=str(getattr(r, "description", "")),
                        source=str(source or ""),
                    )
                )
        except Exception as exc:
            logger.debug("MCP scanner unavailable: %s", exc)
        return findings

    def _scan_plugin(
        self,
        name: str,
        source: str | Path | None,
        metadata: dict[str, Any],
    ) -> list[GateFinding]:
        # Plugins use the same logic as skills
        return self._scan_skill(name, source, metadata)

    def _vt_scan(self, path: Path) -> list[GateFinding]:
        findings: list[GateFinding] = []
        try:
            from sentinel.agent.mcp.virustotal_analyzer import VirusTotalAnalyzer
            vt = VirusTotalAnalyzer(api_key=self._vt_api_key)
            # Scan binary files under path
            targets = [path] if path.is_file() else list(path.rglob("*"))
            for fp in targets:
                if not fp.is_file():
                    continue
                raw_findings = vt.scan_file(str(fp))
                for f in raw_findings:
                    findings.append(
                        GateFinding(
                            rule_id=getattr(f, "rule_id", "VT-001"),
                            severity=str(getattr(f, "severity", "HIGH")),
                            description=str(getattr(f, "description", "VirusTotal detection")),
                            source=str(fp),
                        )
                    )
        except Exception as exc:
            logger.debug("VirusTotal scan unavailable: %s", exc)
        return findings

    # ── Logging ───────────────────────────────────────────────────────

    @staticmethod
    def _log_decision(decision: GateDecision) -> None:
        action_str = decision.action.value.upper()
        finding_count = len(decision.findings)
        if decision.blocked:
            logger.warning(
                "GATE %s: %s %s — %d finding(s): %s",
                action_str,
                decision.component_type.value,
                decision.component_name,
                finding_count,
                decision.reason,
            )
        elif decision.warned:
            logger.info(
                "GATE %s: %s %s — %d finding(s): %s",
                action_str,
                decision.component_type.value,
                decision.component_name,
                finding_count,
                decision.reason,
            )
        else:
            logger.debug(
                "GATE %s: %s %s",
                action_str,
                decision.component_type.value,
                decision.component_name,
            )
