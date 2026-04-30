"""
Eresus Sentinel — Agent Trust Boundary Mapper.

Analyzes agent-tool relationships to identify trust boundary violations:
  - Agents with excessive tool access
  - Tools accessible across trust boundaries
  - Privilege escalation paths through tool chains
  - Missing isolation between agents of different trust levels
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path

from ..finding import Finding, Severity


@dataclass
class AgentNode:
    """Represents an agent in the trust graph."""
    name: str
    trust_level: str = "unknown"  # "system", "user", "external", "untrusted"
    tools: list[str] = field(default_factory=list)
    can_delegate_to: list[str] = field(default_factory=list)
    metadata: dict = field(default_factory=dict)


@dataclass
class ToolNode:
    """Represents a tool in the trust graph."""
    name: str
    capabilities: list[str] = field(default_factory=list)
    risk_level: str = "unknown"  # "safe", "moderate", "dangerous", "critical"
    requires_confirmation: bool = False
    accessible_by: list[str] = field(default_factory=list)


TRUST_LEVELS = {
    "system": 4,    # Highest trust — system-level agent
    "admin": 3,     # Admin-level agent
    "user": 2,      # User-level agent
    "external": 1,  # External/third-party agent
    "untrusted": 0, # Untrusted agent
}

CAPABILITY_RISK = {
    "file_read": "moderate",
    "file_write": "dangerous",
    "file_delete": "critical",
    "command_exec": "critical",
    "network_access": "moderate",
    "database_read": "moderate",
    "database_write": "dangerous",
    "credential_access": "critical",
    "code_eval": "critical",
    "user_data_access": "dangerous",
}

RISK_SEVERITY = {
    "safe": Severity.INFO,
    "moderate": Severity.MEDIUM,
    "dangerous": Severity.HIGH,
    "critical": Severity.CRITICAL,
}


class TrustBoundaryMapper:
    """Maps and analyzes agent-tool trust boundaries."""

    def __init__(self) -> None:
        self.agents: dict[str, AgentNode] = {}
        self.tools: dict[str, ToolNode] = {}
        self.findings: list[Finding] = []

    def load_config(self, config: dict) -> None:
        """Load agent/tool topology from a configuration dictionary.

        Expected format:
        {
            "agents": [
                {"name": "orchestrator", "trust_level": "system", "tools": ["exec_tool"], "delegates_to": ["worker"]},
                {"name": "worker", "trust_level": "user", "tools": ["read_tool"]}
            ],
            "tools": [
                {"name": "exec_tool", "capabilities": ["command_exec"], "requires_confirmation": true},
                {"name": "read_tool", "capabilities": ["file_read"]}
            ]
        }
        """
        for agent_def in config.get("agents", []):
            agent = AgentNode(
                name=agent_def["name"],
                trust_level=agent_def.get("trust_level", "unknown"),
                tools=agent_def.get("tools", []),
                can_delegate_to=agent_def.get("delegates_to", []),
                metadata=agent_def.get("metadata", {}),
            )
            self.agents[agent.name] = agent

        for tool_def in config.get("tools", []):
            caps = tool_def.get("capabilities", [])
            risk = self._compute_tool_risk(caps)
            tool = ToolNode(
                name=tool_def["name"],
                capabilities=caps,
                risk_level=risk,
                requires_confirmation=tool_def.get("requires_confirmation", False),
            )
            self.tools[tool.name] = tool

        # Build reverse mapping (tool -> accessible_by agents)
        for agent in self.agents.values():
            for tool_name in agent.tools:
                if tool_name in self.tools:
                    self.tools[tool_name].accessible_by.append(agent.name)

    def load_file(self, filepath: str) -> None:
        """Load agent/tool topology from a JSON file."""
        path = Path(filepath)
        if not path.exists():
            return
        with open(path, "r", encoding="utf-8") as f:
            config = json.load(f)
        self.load_config(config)

    def analyze(self, source: str = "<config>") -> list[Finding]:
        """Run all trust boundary analyses and return findings."""
        self.findings = []

        self._check_excessive_tool_access(source)
        self._check_cross_boundary_access(source)
        self._check_privilege_escalation(source)
        self._check_dangerous_tools_without_confirmation(source)
        self._check_untrusted_agent_capabilities(source)
        self._check_delegation_trust_violation(source)

        return self.findings

    def _compute_tool_risk(self, capabilities: list[str]) -> str:
        """Compute risk level based on tool capabilities."""
        risk_levels = [CAPABILITY_RISK.get(cap, "safe") for cap in capabilities]
        if "critical" in risk_levels:
            return "critical"
        if "dangerous" in risk_levels:
            return "dangerous"
        if "moderate" in risk_levels:
            return "moderate"
        return "safe"

    def _check_excessive_tool_access(self, source: str) -> None:
        """Flag agents with access to too many tools or dangerous tools."""
        for agent in self.agents.values():
            dangerous_tools = []
            for tool_name in agent.tools:
                tool = self.tools.get(tool_name)
                if tool and tool.risk_level in ("dangerous", "critical"):
                    dangerous_tools.append(tool_name)

            if len(dangerous_tools) >= 3:
                self.findings.append(Finding.agent_mcp(
                    rule_id="TRUST-010",
                    title=f"Excessive dangerous tool access: {agent.name}",
                    description=f"Agent '{agent.name}' (trust_level={agent.trust_level}) has access to "
                                f"{len(dangerous_tools)} dangerous/critical tools: {dangerous_tools}. "
                                "Apply principle of least privilege.",
                    severity=Severity.HIGH,
                    target=source,
                    evidence=f"agent={agent.name}, dangerous_tools={dangerous_tools}",
                ))

    def _check_cross_boundary_access(self, source: str) -> None:
        """Detect tools accessible by agents at different trust levels."""
        for tool_name, tool in self.tools.items():
            if len(tool.accessible_by) < 2:
                continue

            trust_levels = set()
            for agent_name in tool.accessible_by:
                agent = self.agents.get(agent_name)
                if agent:
                    trust_levels.add(agent.trust_level)

            if len(trust_levels) > 1 and tool.risk_level in ("dangerous", "critical"):
                self.findings.append(Finding.agent_mcp(
                    rule_id="TRUST-020",
                    title=f"Cross-boundary tool access: {tool_name}",
                    description=f"Dangerous tool '{tool_name}' (risk={tool.risk_level}) is accessible by agents "
                                f"at different trust levels: {trust_levels}. "
                                "This violates trust boundary isolation.",
                    severity=Severity.CRITICAL,
                    target=source,
                    evidence=f"tool={tool_name}, trust_levels={trust_levels}, agents={tool.accessible_by}",
                ))

    def _check_privilege_escalation(self, source: str) -> None:
        """Detect privilege escalation paths through delegation chains."""
        for agent in self.agents.values():
            agent_level = TRUST_LEVELS.get(agent.trust_level, 0)

            for delegate_name in agent.can_delegate_to:
                delegate = self.agents.get(delegate_name)
                if not delegate:
                    continue

                delegate_level = TRUST_LEVELS.get(delegate.trust_level, 0)

                # Check if delegate has more privileged tools
                agent_max_risk = max(
                    (self._risk_score(self.tools[t].risk_level) for t in agent.tools if t in self.tools),
                    default=0
                )
                delegate_max_risk = max(
                    (self._risk_score(self.tools[t].risk_level) for t in delegate.tools if t in self.tools),
                    default=0
                )

                if agent_level <= delegate_level and delegate_max_risk > agent_max_risk:
                    self.findings.append(Finding.agent_mcp(
                        rule_id="TRUST-030",
                        title=f"Privilege escalation path: {agent.name} -> {delegate_name}",
                        description=f"Agent '{agent.name}' (trust={agent.trust_level}) can delegate to "
                                    f"'{delegate_name}' (trust={delegate.trust_level}) which has access "
                                    f"to more dangerous tools. This enables privilege escalation.",
                        severity=Severity.CRITICAL,
                        target=source,
                        evidence=f"path={agent.name}->{delegate_name}",
                    ))

    def _check_dangerous_tools_without_confirmation(self, source: str) -> None:
        """Flag dangerous tools that don't require user confirmation."""
        for tool_name, tool in self.tools.items():
            if tool.risk_level in ("dangerous", "critical") and not tool.requires_confirmation:
                self.findings.append(Finding.agent_mcp(
                    rule_id="TRUST-040",
                    title=f"Dangerous tool without confirmation: {tool_name}",
                    description=f"Tool '{tool_name}' (risk={tool.risk_level}) does not require user confirmation. "
                                "Dangerous tools should have requires_confirmation=true.",
                    severity=Severity.HIGH,
                    target=source,
                    evidence=f"tool={tool_name}, risk={tool.risk_level}, requires_confirmation=false",
                ))

    def _check_untrusted_agent_capabilities(self, source: str) -> None:
        """Flag untrusted agents with access to any non-safe tools."""
        for agent in self.agents.values():
            if agent.trust_level not in ("untrusted", "external"):
                continue

            for tool_name in agent.tools:
                tool = self.tools.get(tool_name)
                if tool and tool.risk_level != "safe":
                    self.findings.append(Finding.agent_mcp(
                        rule_id="TRUST-050",
                        title=f"Untrusted agent with risky tool: {agent.name}",
                        description=f"Agent '{agent.name}' (trust_level={agent.trust_level}) has access to "
                                    f"tool '{tool_name}' (risk={tool.risk_level}). "
                                    "Untrusted agents should only have safe tool access.",
                        severity=Severity.CRITICAL,
                        target=source,
                        evidence=f"agent={agent.name}, tool={tool_name}, risk={tool.risk_level}",
                    ))

    def _check_delegation_trust_violation(self, source: str) -> None:
        """Flag delegation from higher trust to lower trust agents."""
        for agent in self.agents.values():
            TRUST_LEVELS.get(agent.trust_level, 0)

            for delegate_name in agent.can_delegate_to:
                delegate = self.agents.get(delegate_name)
                if not delegate:
                    self.findings.append(Finding.agent_mcp(
                        rule_id="TRUST-060",
                        title=f"Delegation to unknown agent: {delegate_name}",
                        description=f"Agent '{agent.name}' delegates to '{delegate_name}' which is not defined in the topology. "
                                    "All delegation targets must be explicitly defined.",
                        severity=Severity.MEDIUM,
                        target=source,
                        evidence=f"agent={agent.name}, unknown_delegate={delegate_name}",
                    ))

    @staticmethod
    def _risk_score(risk_level: str) -> int:
        return {"safe": 0, "moderate": 1, "dangerous": 2, "critical": 3}.get(risk_level, 0)
