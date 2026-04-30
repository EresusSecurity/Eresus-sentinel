"""MCP threat taxonomy — STRIDE-aligned threat mapping for MCP servers."""
from __future__ import annotations

from dataclasses import dataclass, field


@dataclass
class MCPThreat:
    id: str
    name: str
    category: str  # STRIDE: Spoofing, Tampering, Repudiation, Info Disclosure, DoS, Elevation
    description: str
    severity: str  # critical, high, medium, low
    mitigations: list[str] = field(default_factory=list)


_MCP_THREAT_TAXONOMY: list[MCPThreat] = [
    MCPThreat("MCP-T001", "Tool Schema Injection", "Tampering",
              "Malicious tool schema manipulates agent behavior", "critical",
              ["Schema validation", "Tool allowlisting", "Input sanitization"]),
    MCPThreat("MCP-T002", "Prompt Injection via Tool Output", "Tampering",
              "Tool returns crafted output to hijack agent", "critical",
              ["Output sanitization", "Agent instruction hardening"]),
    MCPThreat("MCP-T003", "Server Impersonation", "Spoofing",
              "Fake MCP server mimics trusted service", "high",
              ["Server authentication", "TLS verification", "Server allowlisting"]),
    MCPThreat("MCP-T004", "Resource Exfiltration", "Information Disclosure",
              "MCP server exposes sensitive data via resources", "high",
              ["Resource access control", "Data classification", "Audit logging"]),
    MCPThreat("MCP-T005", "Tool Abuse for Lateral Movement", "Elevation of Privilege",
              "Agent misuses tool capabilities to access unauthorized systems", "high",
              ["Least privilege", "Tool permission boundaries", "Execution sandboxing"]),
    MCPThreat("MCP-T006", "Denial of Service via Tool Calls", "Denial of Service",
              "Excessive or malformed tool calls overwhelm server", "medium",
              ["Rate limiting", "Timeout enforcement", "Resource quotas"]),
    MCPThreat("MCP-T007", "Unlogged Tool Execution", "Repudiation",
              "Tool actions not properly logged for audit", "medium",
              ["Comprehensive audit logging", "Immutable logs", "Log integrity checks"]),
    MCPThreat("MCP-T008", "Shadow MCP Server", "Spoofing",
              "Unauthorized MCP server discovered in project", "high",
              ["Server inventory", "Periodic scanning", "Config auditing"]),
    MCPThreat("MCP-T009", "Overprivileged Tool Definitions", "Elevation of Privilege",
              "Tools define broader capabilities than needed", "medium",
              ["Minimum required permissions", "Tool scope review", "Capability analysis"]),
    MCPThreat("MCP-T010", "Vulnerable Server Dependencies", "Tampering",
              "MCP server has known vulnerable packages", "high",
              ["Dependency scanning", "Version pinning", "Regular updates"]),
]


class ThreatTaxonomy:
    """MCP threat taxonomy lookup and mapping."""

    def __init__(self) -> None:
        self._threats = {t.id: t for t in _MCP_THREAT_TAXONOMY}

    def get(self, threat_id: str) -> MCPThreat | None:
        return self._threats.get(threat_id)

    def by_category(self, category: str) -> list[MCPThreat]:
        return [t for t in self._threats.values() if t.category == category]

    def by_severity(self, severity: str) -> list[MCPThreat]:
        return [t for t in self._threats.values() if t.severity == severity]

    def all_threats(self) -> list[MCPThreat]:
        return list(self._threats.values())

    @property
    def size(self) -> int:
        return len(self._threats)
