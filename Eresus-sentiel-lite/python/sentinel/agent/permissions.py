"""
Eresus Sentinel — Agent Permission Analyzer.

Evaluates agent permission configurations for:
  - Excessive permissions (principle of least privilege)
  - Missing permission boundaries
  - Implicit permission inheritance
  - Permission conflicts and overlaps
  - Sensitive action coverage gaps
"""

from __future__ import annotations

import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

from ..finding import Finding, Severity


@dataclass
class PermissionSet:
    """Represents a set of permissions for an agent."""
    agent_name: str
    allowed: Set[str] = field(default_factory=set)
    denied: Set[str] = field(default_factory=set)
    scopes: Set[str] = field(default_factory=set)
    requires_approval: Set[str] = field(default_factory=set)
    inherits_from: Optional[str] = None


# Critical actions that always require explicit permission
CRITICAL_ACTIONS = {
    "file:write", "file:delete", "file:execute",
    "command:exec", "command:shell",
    "network:external", "network:dns",
    "database:write", "database:drop", "database:admin",
    "credential:read", "credential:create", "credential:delete",
    "user:impersonate", "user:elevate",
    "system:reboot", "system:config", "system:install",
    "payment:charge", "payment:refund",
    "email:send", "email:bulk",
    "model:deploy", "model:delete", "model:train",
    "data:export", "data:delete", "data:share",
    "code:eval", "code:deploy",
    "container:create", "container:delete",
    "cloud:provision", "cloud:destroy",
}

# Read-only / informational actions
SAFE_ACTIONS = {
    "file:read", "file:list",
    "network:internal",
    "database:read",
    "model:infer", "model:list",
    "data:read", "data:list",
    "log:read",
}


class PermissionAnalyzer:
    """Analyzes agent permission configurations for security issues."""

    def __init__(self) -> None:
        self.findings: list[Finding] = []
        self.permission_sets: dict[str, PermissionSet] = {}

    def load_config(self, config: dict) -> None:
        """Load permission configuration.

        Expected format:
        {
            "agents": [
                {
                    "name": "assistant",
                    "permissions": {
                        "allowed": ["file:read", "database:read"],
                        "denied": ["command:exec"],
                        "scopes": ["internal"],
                        "requires_approval": ["file:write"],
                        "inherits_from": "base_agent"
                    }
                }
            ]
        }
        """
        for agent_def in config.get("agents", []):
            perms = agent_def.get("permissions", {})
            ps = PermissionSet(
                agent_name=agent_def["name"],
                allowed=set(perms.get("allowed", [])),
                denied=set(perms.get("denied", [])),
                scopes=set(perms.get("scopes", [])),
                requires_approval=set(perms.get("requires_approval", [])),
                inherits_from=perms.get("inherits_from"),
            )
            self.permission_sets[agent_def["name"]] = ps

    def load_file(self, filepath: str) -> None:
        """Load permission configuration from a JSON file."""
        path = Path(filepath)
        if not path.exists():
            return
        with open(path, "r", encoding="utf-8") as f:
            config = json.load(f)
        self.load_config(config)

    def analyze(self, source: str = "<config>") -> list[Finding]:
        """Run all permission analyses and return findings."""
        self.findings = []

        for ps in self.permission_sets.values():
            self._check_excessive_permissions(ps, source)
            self._check_critical_without_approval(ps, source)
            self._check_permission_conflicts(ps, source)
            self._check_no_deny_list(ps, source)
            self._check_scope_missing(ps, source)
            self._check_wildcard_permissions(ps, source)

        self._check_inheritance_chains(source)

        return self.findings

    def _resolve_permissions(self, ps: PermissionSet) -> Set[str]:
        """Resolve effective permissions including inheritance."""
        effective = set(ps.allowed)
        if ps.inherits_from and ps.inherits_from in self.permission_sets:
            parent = self.permission_sets[ps.inherits_from]
            effective |= self._resolve_permissions(parent)
        effective -= ps.denied
        return effective

    def _check_excessive_permissions(self, ps: PermissionSet, source: str) -> None:
        """Flag agents with too many critical permissions."""
        effective = self._resolve_permissions(ps)
        critical_granted = effective & CRITICAL_ACTIONS

        if len(critical_granted) >= 5:
            self.findings.append(Finding.agent_mcp(
                rule_id="PERM-010",
                title=f"Excessive critical permissions: {ps.agent_name}",
                description=f"Agent '{ps.agent_name}' has {len(critical_granted)} critical permissions: "
                            f"{sorted(critical_granted)}. Apply principle of least privilege.",
                severity=Severity.HIGH,
                target=source,
                evidence=f"agent={ps.agent_name}, critical_count={len(critical_granted)}",
            ))

        if len(effective) > 20:
            self.findings.append(Finding.agent_mcp(
                rule_id="PERM-011",
                title=f"Broad permission set: {ps.agent_name}",
                description=f"Agent '{ps.agent_name}' has {len(effective)} total permissions. "
                            "Consider narrowing the scope.",
                severity=Severity.MEDIUM,
                target=source,
                evidence=f"agent={ps.agent_name}, total_perms={len(effective)}",
            ))

    def _check_critical_without_approval(self, ps: PermissionSet, source: str) -> None:
        """Flag critical actions allowed without human approval."""
        effective = self._resolve_permissions(ps)
        critical_granted = effective & CRITICAL_ACTIONS
        no_approval = critical_granted - ps.requires_approval

        for action in sorted(no_approval):
            self.findings.append(Finding.agent_mcp(
                rule_id="PERM-020",
                title=f"Critical action without approval: {action}",
                description=f"Agent '{ps.agent_name}' can perform '{action}' without human approval. "
                            "Add this action to requires_approval.",
                severity=Severity.HIGH,
                target=source,
                evidence=f"agent={ps.agent_name}, action={action}",
            ))

    def _check_permission_conflicts(self, ps: PermissionSet, source: str) -> None:
        """Flag permissions that are both allowed and denied."""
        conflicts = ps.allowed & ps.denied
        for action in sorted(conflicts):
            self.findings.append(Finding.agent_mcp(
                rule_id="PERM-030",
                title=f"Permission conflict: {action}",
                description=f"Agent '{ps.agent_name}' has '{action}' in both allowed and denied sets. "
                            "Resolve this ambiguity.",
                severity=Severity.MEDIUM,
                target=source,
                evidence=f"agent={ps.agent_name}, conflicted={action}",
            ))

    def _check_no_deny_list(self, ps: PermissionSet, source: str) -> None:
        """Flag agents with no explicit deny list."""
        if not ps.denied and ps.allowed:
            self.findings.append(Finding.agent_mcp(
                rule_id="PERM-040",
                title=f"No deny list: {ps.agent_name}",
                description=f"Agent '{ps.agent_name}' has allowed permissions but no explicit deny list. "
                            "Use deny lists for defense in depth.",
                severity=Severity.LOW,
                target=source,
                evidence=f"agent={ps.agent_name}",
            ))

    def _check_scope_missing(self, ps: PermissionSet, source: str) -> None:
        """Flag agents with critical permissions but no scope restriction."""
        effective = self._resolve_permissions(ps)
        has_critical = bool(effective & CRITICAL_ACTIONS)

        if has_critical and not ps.scopes:
            self.findings.append(Finding.agent_mcp(
                rule_id="PERM-050",
                title=f"No scope restriction: {ps.agent_name}",
                description=f"Agent '{ps.agent_name}' has critical permissions but no scope restriction. "
                            "Add scopes to limit the blast radius (e.g., 'internal', 'project:X').",
                severity=Severity.MEDIUM,
                target=source,
                evidence=f"agent={ps.agent_name}",
            ))

    def _check_wildcard_permissions(self, ps: PermissionSet, source: str) -> None:
        """Flag wildcard or overly broad permissions."""
        for action in ps.allowed:
            if action in ("*", "all", "admin", "root", "superuser"):
                self.findings.append(Finding.agent_mcp(
                    rule_id="PERM-060",
                    title=f"Wildcard permission: {ps.agent_name}",
                    description=f"Agent '{ps.agent_name}' has wildcard permission '{action}'. "
                                "Never grant blanket access.",
                    severity=Severity.CRITICAL,
                    target=source,
                    evidence=f"agent={ps.agent_name}, permission={action}",
                ))

    def _check_inheritance_chains(self, source: str) -> None:
        """Detect circular or deep inheritance chains."""
        for ps in self.permission_sets.values():
            visited = set()
            current = ps
            depth = 0

            while current and current.inherits_from:
                if current.agent_name in visited:
                    self.findings.append(Finding.agent_mcp(
                        rule_id="PERM-070",
                        title=f"Circular permission inheritance: {ps.agent_name}",
                        description=f"Agent '{ps.agent_name}' has circular inheritance chain. "
                                    "This could lead to unexpected permission escalation.",
                        severity=Severity.HIGH,
                        target=source,
                        evidence=f"agent={ps.agent_name}, chain={visited}",
                    ))
                    break

                visited.add(current.agent_name)
                depth += 1
                current = self.permission_sets.get(current.inherits_from)

            if depth > 5:
                self.findings.append(Finding.agent_mcp(
                    rule_id="PERM-071",
                    title=f"Deep inheritance chain: {ps.agent_name}",
                    description=f"Agent '{ps.agent_name}' has inheritance depth {depth}. "
                                "Deep chains make permission auditing difficult.",
                    severity=Severity.MEDIUM,
                    target=source,
                    evidence=f"agent={ps.agent_name}, depth={depth}",
                ))
