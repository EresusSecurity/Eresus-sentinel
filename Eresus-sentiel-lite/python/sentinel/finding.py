"""
Universal Finding Data Model for Eresus Sentinel.

Every security module produces findings conforming to this schema.
Enables unified reporting, scoring, deduplication, and correlation
across all 7 security domains.
"""

from __future__ import annotations

import json
import uuid
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Optional


class Severity(str, Enum):
    """Finding severity levels aligned with CVSS qualitative ratings."""
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"

    @property
    def sort_key(self) -> int:
        return {
            Severity.CRITICAL: 0,
            Severity.HIGH: 1,
            Severity.MEDIUM: 2,
            Severity.LOW: 3,
            Severity.INFO: 4,
        }[self]


class Module(str, Enum):
    """Security module identifiers."""
    ARTIFACT = "artifact_scanner"
    INPUT_FIREWALL = "input_firewall"
    OUTPUT_FIREWALL = "output_firewall"
    RED_TEAM = "red_team"
    SAST = "sast"
    AGENT_MCP = "agent_mcp"
    SUPPLY_CHAIN = "supply_chain"


@dataclass
class Location:
    """Source location for a finding — supports both code and binary artifacts."""
    file: Optional[str] = None
    line_start: Optional[int] = None
    line_end: Optional[int] = None
    col_start: Optional[int] = None
    col_end: Optional[int] = None
    byte_offset: Optional[int] = None

    def __str__(self) -> str:
        if self.file and self.line_start:
            end = f"-{self.line_end}" if self.line_end else ""
            return f"{self.file}:{self.line_start}{end}"
        if self.file and self.byte_offset is not None:
            return f"{self.file}@0x{self.byte_offset:x}"
        return self.file or "<unknown>"


@dataclass
class Exploitability:
    """Exploitability assessment for red team and artifact findings."""
    attack_vector: str          # "direct_input", "latent_injection", "encoded", "deserialization"
    complexity: str             # "LOW", "MEDIUM", "HIGH"
    requires_auth: bool = False
    impact_scope: str = "model"  # "model", "application", "infrastructure"


@dataclass
class AttemptData:
    """
    Red team attempt data — tracks the full probe → response → detection cycle.
    Provides structured audit trails for security testing.
    """
    probe_classname: str
    prompt: str
    response: Optional[str] = None
    detector_classname: Optional[str] = None
    detector_score: float = 0.0
    conversation_history: list = field(default_factory=list)
    encoding_used: Optional[str] = None


@dataclass
class Finding:
    """
    Universal finding schema for Eresus Sentinel.

    Design principles:
    - Every field has a clear owner (which module sets it)
    - Classification fields map directly to OWASP LLM Top 10, CWE, MITRE ATLAS, AVID
    - Evidence is always captured for auditability
    - Optional exploitability data for red team findings
    """

    # --- Identity ---
    rule_id: str                           # e.g. "ARTIFACT-001", "FIREWALL-INPUT-003"
    module: str                            # Module enum value
    title: str                             # Human-readable title
    description: str                       # Detailed explanation

    # --- Classification ---
    severity: Severity
    confidence: float                      # 0.0 - 1.0
    category: str = ""                     # OWASP LLM Top 10 category name
    cwe_ids: list[str] = field(default_factory=list)
    owasp_llm: Optional[str] = None        # e.g. "LLM01" (Prompt Injection)
    tags: list[str] = field(default_factory=list)  # MISP-format taxonomy tags

    # --- Location ---
    target: str = ""                       # file path, URL, model name
    location: Optional[Location] = None

    # --- Evidence ---
    evidence: str = ""                     # Extracted evidence
    remediation: str = ""                  # Actionable fix guidance

    # --- Policy ---
    action: str = "BLOCK"                  # "BLOCK" or "WARN" — set by post-processing pipeline

    # --- Auto-populated ---
    id: str = field(default_factory=lambda: str(uuid.uuid4()))
    timestamp: str = field(default_factory=lambda: datetime.now(timezone.utc).isoformat())
    scan_id: str = ""                      # Links to parent scan session

    # --- Optional (Red Team) ---
    exploitability: Optional[Exploitability] = None
    attempt_data: Optional[AttemptData] = None

    @property
    def fingerprint(self) -> str:
        """Deterministic fingerprint for deduplication across scans."""
        import hashlib
        key = f"{self.rule_id}|{self.target}|{self.evidence[:200]}"
        return hashlib.sha256(key.encode()).hexdigest()[:16]

    def to_dict(self) -> dict:
        """Serialize finding to a dictionary, handling nested dataclasses."""
        data = asdict(self)
        data["severity"] = self.severity.value
        data["fingerprint"] = self.fingerprint
        return data

    def to_json(self, indent: int = 2) -> str:
        """Serialize finding to JSON string."""
        return json.dumps(self.to_dict(), indent=indent, default=str)

    def __lt__(self, other: Finding) -> bool:
        """Allow sorting findings by severity (critical first)."""
        if not isinstance(other, Finding):
            return NotImplemented
        return self.severity.sort_key < other.severity.sort_key

    def to_sarif_result(self) -> dict:
        """
        Convert finding to SARIF 2.1.0 result format.
        See: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
        """
        result = {
            "ruleId": self.rule_id,
            "level": self._severity_to_sarif_level(),
            "message": {
                "text": self.description
            },
            "properties": {
                "confidence": self.confidence,
                "module": self.module,
                "tags": self.tags,
            }
        }

        if self.location:
            result["locations"] = [{
                "physicalLocation": self._build_sarif_location()
            }]

        if self.evidence:
            result["properties"]["evidence"] = self.evidence

        return result

    def _severity_to_sarif_level(self) -> str:
        mapping = {
            Severity.CRITICAL: "error",
            Severity.HIGH: "error",
            Severity.MEDIUM: "warning",
            Severity.LOW: "note",
            Severity.INFO: "note",
        }
        return mapping[self.severity]

    def _build_sarif_location(self) -> dict:
        loc = {}
        if self.location and self.location.file:
            loc["artifactLocation"] = {"uri": self.location.file}
            if self.location.line_start is not None:
                loc["region"] = {
                    "startLine": self.location.line_start,
                }
                if self.location.line_end is not None:
                    loc["region"]["endLine"] = self.location.line_end
                if self.location.col_start is not None:
                    loc["region"]["startColumn"] = self.location.col_start
        return loc

    @classmethod
    def artifact(
        cls,
        rule_id: str,
        title: str,
        description: str,
        severity: Severity,
        target: str = "",
        evidence: str = "",
        confidence: float = 1.0,
        source: str = "",
        **kwargs,
    ) -> Finding:
        """Factory for artifact scanner findings.

        Accepts 'source' as alias for 'target' for convenience.
        """
        resolved_target = target or source
        return cls(
            rule_id=rule_id,
            module=Module.ARTIFACT.value,
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            target=resolved_target,
            evidence=evidence,
            category="Model Artifact Security",
            owasp_llm="LLM05",
            **kwargs,
        )

    @classmethod
    def firewall_input(
        cls,
        rule_id: str,
        title: str,
        description: str,
        severity: Severity,
        target: str = "",
        evidence: str = "",
        confidence: float = 0.9,
        source: str = "",
        **kwargs,
    ) -> Finding:
        """Factory for input firewall findings.

        Accepts 'source' as alias for 'target' for convenience.
        """
        resolved_target = target or source
        return cls(
            rule_id=rule_id,
            module=Module.INPUT_FIREWALL.value,
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            target=resolved_target,
            evidence=evidence,
            category="Prompt Injection",
            owasp_llm="LLM01",
            **kwargs,
        )

    @classmethod
    def firewall_output(
        cls,
        rule_id: str,
        title: str,
        description: str,
        severity: Severity,
        target: str = "",
        evidence: str = "",
        confidence: float = 0.9,
        source: str = "",
        **kwargs,
    ) -> Finding:
        """Factory for output firewall findings.

        Accepts 'source' as alias for 'target' for convenience.
        """
        resolved_target = target or source
        return cls(
            rule_id=rule_id,
            module=Module.OUTPUT_FIREWALL.value,
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            target=resolved_target,
            evidence=evidence,
            category="Sensitive Information Disclosure",
            owasp_llm="LLM06",
            **kwargs,
        )

    @classmethod
    def agent_mcp(
        cls,
        rule_id: str,
        title: str,
        description: str,
        severity: Severity,
        target: str = "",
        evidence: str = "",
        confidence: float = 0.9,
        source: str = "",
        **kwargs,
    ) -> Finding:
        """Factory for Agent/MCP security findings.

        Accepts 'source' as alias for 'target' for convenience.
        """
        resolved_target = target or source
        return cls(
            rule_id=rule_id,
            module=Module.AGENT_MCP.value,
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            target=resolved_target,
            evidence=evidence,
            category="Agent/MCP Security",
            owasp_llm="LLM07",
            **kwargs,
        )

    @classmethod
    def supply_chain(
        cls,
        rule_id: str,
        title: str,
        description: str,
        severity: Severity,
        target: str = "",
        evidence: str = "",
        confidence: float = 0.9,
        source: str = "",
        **kwargs,
    ) -> Finding:
        """Factory for Supply Chain security findings.

        Accepts 'source' as alias for 'target' for convenience.
        """
        resolved_target = target or source
        return cls(
            rule_id=rule_id,
            module=Module.SUPPLY_CHAIN.value,
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            target=resolved_target,
            evidence=evidence,
            category="Supply Chain Security",
            owasp_llm="LLM05",
            **kwargs,
        )

    @classmethod
    def red_team(
        cls,
        rule_id: str,
        title: str,
        description: str,
        severity: Severity,
        target: str = "",
        evidence: str = "",
        confidence: float = 0.9,
        source: str = "",
        **kwargs,
    ) -> Finding:
        """Factory for Red Team / Adversarial testing findings.

        Accepts 'source' as alias for 'target' for convenience.
        """
        resolved_target = target or source
        return cls(
            rule_id=rule_id,
            module=Module.RED_TEAM.value,
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            target=resolved_target,
            evidence=evidence,
            category="Red Team / Adversarial Testing",
            owasp_llm="LLM09",
            **kwargs,
        )


    @classmethod
    def sast(
        cls,
        rule_id: str,
        title: str,
        description: str,
        severity: Severity,
        target: str = "",
        evidence: str = "",
        confidence: float = 0.85,
        source: str = "",
        **kwargs,
    ) -> Finding:
        """Factory for SAST / static analysis findings."""
        resolved_target = target or source
        return cls(
            rule_id=rule_id,
            module=Module.SAST.value,
            title=title,
            description=description,
            severity=severity,
            confidence=confidence,
            target=resolved_target,
            evidence=evidence,
            category="Static Analysis",
            owasp_llm="LLM05",
            **kwargs,
        )


def merge_findings(findings: list[Finding], deduplicate: bool = True) -> list[Finding]:
    """Merge and optionally deduplicate findings from multiple scans."""
    if not deduplicate:
        return sorted(findings)

    seen: set[str] = set()
    merged: list[Finding] = []
    for f in sorted(findings):
        fp = f.fingerprint
        if fp not in seen:
            seen.add(fp)
            merged.append(f)
    return merged
