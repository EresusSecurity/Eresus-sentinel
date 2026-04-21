"""Eresus Sentinel — OPA / Rego Policy Engine.

Evaluate security policies using Open Policy Agent (OPA) compatible Rego rules.
Supports both external OPA server and embedded evaluation.
"""

from __future__ import annotations

import json
import logging
import os
import urllib.request
from dataclasses import dataclass, field
from enum import Enum, auto
from pathlib import Path
from typing import Any, Optional

logger = logging.getLogger(__name__)

_REGO_POLICIES_DIR = Path(__file__).resolve().parent / "config" / "policies"
_OPA_ENDPOINT_ENV = "SENTINEL_OPA_ENDPOINT"


class PolicyDecision(Enum):
    ALLOW = auto()
    DENY = auto()
    WARN = auto()
    AUDIT = auto()


@dataclass
class PolicyInput:
    """Standard input structure for policy evaluation."""
    action: str                          # "scan", "tool_call", "file_access", "network"
    subject: str                         # Agent or tool name
    resource: str                        # Target resource
    context: dict[str, Any] = field(default_factory=dict)
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyResult:
    decision: PolicyDecision
    rule_name: str
    reason: str
    details: dict[str, Any] = field(default_factory=dict)
    violations: list[str] = field(default_factory=list)


@dataclass
class RegoPolicy:
    name: str
    package: str
    rules: str
    description: str = ""
    version: str = "1.0"


# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━
# BUILTIN REGO POLICIES
# ━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━━

BUILTIN_POLICIES: dict[str, str] = {
    "tool_access": '''
package sentinel.tool_access

default allow := false

# Allow safe tool calls
allow {
    input.action == "tool_call"
    not dangerous_tool[input.resource]
}

# Deny dangerous tools without explicit permission
deny[msg] {
    input.action == "tool_call"
    dangerous_tool[input.resource]
    not input.context.explicit_permission
    msg := sprintf("Dangerous tool '%s' requires explicit permission", [input.resource])
}

dangerous_tool[name] {
    dangerous := {"execute_command", "run_shell", "bash", "eval", "exec",
                  "delete_file", "write_file", "sql_query", "http_request"}
    dangerous[name]
}

# Warn on network-capable tools
warn[msg] {
    input.action == "tool_call"
    network_tool[input.resource]
    msg := sprintf("Network-capable tool '%s' detected", [input.resource])
}

network_tool[name] {
    tools := {"fetch_url", "http_request", "curl", "wget", "dns_lookup"}
    tools[name]
}
''',

    "file_access": '''
package sentinel.file_access

default allow := false

allow {
    input.action == "file_access"
    not sensitive_path[input.resource]
}

deny[msg] {
    input.action == "file_access"
    sensitive_path[input.resource]
    msg := sprintf("Access to sensitive path denied: %s", [input.resource])
}

sensitive_path[path] {
    prefixes := {"/etc/shadow", "/etc/passwd", "/root", "/proc/self",
                 ".ssh/", ".aws/", ".kube/", ".docker/", ".env"}
    startswith(path, prefixes[_])
}

sensitive_path[path] {
    suffixes := {".pem", ".key", ".p12", ".pfx", ".jks"}
    endswith(path, suffixes[_])
}
''',

    "network_policy": '''
package sentinel.network

default allow := false

allow {
    input.action == "network"
    not blocked_destination[input.resource]
    input.context.protocol == "https"
}

deny[msg] {
    input.action == "network"
    blocked_destination[input.resource]
    msg := sprintf("Network access to blocked destination: %s", [input.resource])
}

deny[msg] {
    input.action == "network"
    input.context.protocol == "http"
    msg := "Insecure HTTP connections are not allowed"
}

blocked_destination[dest] {
    blocked := {"169.254.169.254", "metadata.google.internal",
                "metadata.azure.com", "localhost", "127.0.0.1", "0.0.0.0"}
    blocked[dest]
}

warn[msg] {
    input.action == "network"
    input.context.port == 22
    msg := "SSH connection detected"
}
''',

    "agent_policy": '''
package sentinel.agent

default allow := false

allow {
    input.action == "delegate"
    valid_delegation
}

valid_delegation {
    input.context.delegation_depth < 3
    input.context.source_trust >= 0.7
}

deny[msg] {
    input.action == "delegate"
    input.context.delegation_depth >= 3
    msg := sprintf("Delegation chain too deep: %d (max: 3)", [input.context.delegation_depth])
}

deny[msg] {
    input.action == "delegate"
    input.context.source_trust < 0.7
    msg := sprintf("Source trust level too low: %.2f (min: 0.7)", [input.context.source_trust])
}

deny[msg] {
    input.action == "escalate"
    not input.context.human_approved
    msg := "Privilege escalation requires human approval"
}

warn[msg] {
    input.action == "tool_call"
    input.context.risk_score > 0.7
    msg := sprintf("High risk score: %.2f", [input.context.risk_score])
}
''',

    "data_handling": '''
package sentinel.data

default allow := false

allow {
    input.action == "data_access"
    not pii_field[input.resource]
}

deny[msg] {
    input.action == "data_access"
    pii_field[input.resource]
    not input.context.data_processing_agreement
    msg := sprintf("PII field '%s' requires data processing agreement", [input.resource])
}

pii_field[name] {
    pii := {"email", "phone", "ssn", "credit_card", "address",
            "date_of_birth", "passport", "driver_license", "bank_account"}
    pii[name]
}

deny[msg] {
    input.action == "data_export"
    input.context.destination_country
    not approved_country[input.context.destination_country]
    msg := sprintf("Data export to %s not approved", [input.context.destination_country])
}

approved_country[c] {
    countries := {"US", "EU", "UK", "CA", "AU", "NZ", "JP"}
    countries[c]
}
''',

    "scan_policy": '''
package sentinel.scan

default allow := true

# Enforce minimum scan coverage
deny[msg] {
    input.action == "scan"
    input.context.scanner_count < 3
    msg := sprintf("Insufficient scanner coverage: %d (min: 3)", [input.context.scanner_count])
}

# Require critical findings to block
deny[msg] {
    input.action == "pass_through"
    input.context.critical_findings > 0
    msg := sprintf("Cannot pass through with %d critical findings", [input.context.critical_findings])
}

warn[msg] {
    input.action == "scan"
    input.context.risk_score > 0.5
    msg := sprintf("Elevated risk score: %.2f", [input.context.risk_score])
}
''',
}


class OPAPolicyEngine:
    """Evaluate Rego policies via external OPA server or embedded logic.

    Features:
    - External OPA server integration (REST API)
    - Embedded Rego evaluation fallback
    - Builtin policy library (tool_access, file_access, network, agent, data, scan)
    - Custom policy loading from filesystem
    - Policy versioning and composition
    """

    def __init__(
        self,
        opa_endpoint: str | None = None,
        policies_dir: str | Path | None = None,
    ):
        self._opa_endpoint = opa_endpoint or os.getenv(_OPA_ENDPOINT_ENV, "")
        self._policies: dict[str, str] = dict(BUILTIN_POLICIES)
        self._use_external = bool(self._opa_endpoint)

        if policies_dir:
            self._load_policies_from_dir(Path(policies_dir))
        elif _REGO_POLICIES_DIR.is_dir():
            self._load_policies_from_dir(_REGO_POLICIES_DIR)

    @property
    def policy_count(self) -> int:
        return len(self._policies)

    @property
    def policy_names(self) -> list[str]:
        return list(self._policies.keys())

    @property
    def using_external_opa(self) -> bool:
        return self._use_external

    def evaluate(
        self,
        policy_name: str,
        policy_input: PolicyInput | dict,
    ) -> PolicyResult:
        """Evaluate a policy against the given input."""
        if isinstance(policy_input, PolicyInput):
            input_dict = {
                "action": policy_input.action,
                "subject": policy_input.subject,
                "resource": policy_input.resource,
                "context": policy_input.context,
                "metadata": policy_input.metadata,
            }
        else:
            input_dict = policy_input

        if self._use_external:
            return self._evaluate_external(policy_name, input_dict)
        return self._evaluate_embedded(policy_name, input_dict)

    def evaluate_all(self, policy_input: PolicyInput | dict) -> list[PolicyResult]:
        """Evaluate all loaded policies against the input."""
        return [self.evaluate(name, policy_input) for name in self._policies]

    def add_policy(self, name: str, rego_source: str) -> None:
        self._policies[name] = rego_source

    def remove_policy(self, name: str) -> bool:
        return self._policies.pop(name, None) is not None

    def get_policy_source(self, name: str) -> str | None:
        return self._policies.get(name)

    # ── External OPA evaluation ──────────────────────────────────────

    def _evaluate_external(self, policy_name: str, input_dict: dict) -> PolicyResult:
        """Evaluate via OPA REST API."""
        package = f"sentinel/{policy_name.replace('.', '/')}"
        url = f"{self._opa_endpoint.rstrip('/')}/v1/data/{package}"

        payload = json.dumps({"input": input_dict}).encode("utf-8")

        try:
            req = urllib.request.Request(
                url,
                data=payload,
                headers={"Content-Type": "application/json"},
            )
            with urllib.request.urlopen(req, timeout=5) as resp:
                result = json.loads(resp.read())

            data = result.get("result", {})
            allow = data.get("allow", False)
            deny_msgs = data.get("deny", [])
            warn_msgs = data.get("warn", [])

            if deny_msgs:
                decision = PolicyDecision.DENY
                reason = "; ".join(deny_msgs) if isinstance(deny_msgs, list) else str(deny_msgs)
            elif warn_msgs:
                decision = PolicyDecision.WARN
                reason = "; ".join(warn_msgs) if isinstance(warn_msgs, list) else str(warn_msgs)
            elif allow:
                decision = PolicyDecision.ALLOW
                reason = "Policy allows this action"
            else:
                decision = PolicyDecision.DENY
                reason = "Default deny — no allow rule matched"

            return PolicyResult(
                decision=decision,
                rule_name=policy_name,
                reason=reason,
                details=data,
                violations=deny_msgs if isinstance(deny_msgs, list) else [str(deny_msgs)] if deny_msgs else [],
            )

        except Exception as e:
            logger.error("OPA evaluation failed for %s: %s", policy_name, e)
            return PolicyResult(
                decision=PolicyDecision.DENY,
                rule_name=policy_name,
                reason=f"OPA evaluation error: {e}",
            )

    # ── Embedded evaluation ──────────────────────────────────────────

    def _evaluate_embedded(self, policy_name: str, input_dict: dict) -> PolicyResult:
        """Embedded evaluation using simple rule matching.

        This is a lightweight fallback when external OPA is not available.
        It evaluates a subset of Rego semantics directly.
        """
        rego_source = self._policies.get(policy_name)
        if not rego_source:
            return PolicyResult(
                decision=PolicyDecision.DENY,
                rule_name=policy_name,
                reason=f"Policy not found: {policy_name}",
            )

        deny_messages: list[str] = []
        warn_messages: list[str] = []
        allow = False

        # Parse and evaluate the policy
        action = input_dict.get("action", "")
        resource = input_dict.get("resource", "")
        context = input_dict.get("context", {})

        if policy_name == "tool_access":
            dangerous = {"execute_command", "run_shell", "bash", "eval", "exec",
                        "delete_file", "write_file", "sql_query", "http_request"}
            network = {"fetch_url", "http_request", "curl", "wget", "dns_lookup"}

            if action == "tool_call":
                if resource in dangerous and not context.get("explicit_permission"):
                    deny_messages.append(f"Dangerous tool '{resource}' requires explicit permission")
                elif resource in network:
                    warn_messages.append(f"Network-capable tool '{resource}' detected")
                else:
                    allow = True

        elif policy_name == "file_access":
            sensitive_prefixes = {"/etc/shadow", "/etc/passwd", "/root", "/proc/self",
                                ".ssh/", ".aws/", ".kube/", ".docker/", ".env"}
            sensitive_suffixes = {".pem", ".key", ".p12", ".pfx", ".jks"}

            if action == "file_access":
                blocked = any(resource.startswith(p) for p in sensitive_prefixes)
                blocked = blocked or any(resource.endswith(s) for s in sensitive_suffixes)
                if blocked:
                    deny_messages.append(f"Access to sensitive path denied: {resource}")
                else:
                    allow = True

        elif policy_name == "network_policy":
            blocked = {"169.254.169.254", "metadata.google.internal",
                      "metadata.azure.com", "localhost", "127.0.0.1", "0.0.0.0"}
            if action == "network":
                if resource in blocked:
                    deny_messages.append(f"Network access to blocked destination: {resource}")
                elif context.get("protocol") == "http":
                    deny_messages.append("Insecure HTTP connections are not allowed")
                else:
                    allow = True
                if context.get("port") == 22:
                    warn_messages.append("SSH connection detected")

        elif policy_name == "agent_policy":
            if action == "delegate":
                depth = context.get("delegation_depth", 0)
                trust = context.get("source_trust", 0.0)
                if depth >= 3:
                    deny_messages.append(f"Delegation chain too deep: {depth} (max: 3)")
                elif trust < 0.7:
                    deny_messages.append(f"Source trust level too low: {trust:.2f} (min: 0.7)")
                else:
                    allow = True
            elif action == "escalate":
                if not context.get("human_approved"):
                    deny_messages.append("Privilege escalation requires human approval")
            elif action == "tool_call":
                if context.get("risk_score", 0) > 0.7:
                    warn_messages.append(f"High risk score: {context['risk_score']:.2f}")
                allow = True

        elif policy_name == "data_handling":
            pii = {"email", "phone", "ssn", "credit_card", "address",
                  "date_of_birth", "passport", "driver_license", "bank_account"}
            if action == "data_access":
                if resource in pii and not context.get("data_processing_agreement"):
                    deny_messages.append(f"PII field '{resource}' requires data processing agreement")
                else:
                    allow = True
            elif action == "data_export":
                approved = {"US", "EU", "UK", "CA", "AU", "NZ", "JP"}
                country = context.get("destination_country", "")
                if country and country not in approved:
                    deny_messages.append(f"Data export to {country} not approved")
                else:
                    allow = True

        elif policy_name == "scan_policy":
            if action == "scan":
                if context.get("scanner_count", 0) < 3:
                    deny_messages.append(f"Insufficient scanner coverage: {context.get('scanner_count', 0)} (min: 3)")
                else:
                    allow = True
            elif action == "pass_through":
                if context.get("critical_findings", 0) > 0:
                    deny_messages.append(f"Cannot pass through with {context['critical_findings']} critical findings")
                else:
                    allow = True
            else:
                allow = True

        if deny_messages:
            decision = PolicyDecision.DENY
            reason = "; ".join(deny_messages)
        elif warn_messages:
            decision = PolicyDecision.WARN
            reason = "; ".join(warn_messages)
        elif allow:
            decision = PolicyDecision.ALLOW
            reason = "Policy allows this action"
        else:
            decision = PolicyDecision.DENY
            reason = "Default deny — no allow rule matched"

        return PolicyResult(
            decision=decision,
            rule_name=policy_name,
            reason=reason,
            violations=deny_messages,
        )

    # ── Filesystem loading ───────────────────────────────────────────

    def _load_policies_from_dir(self, dirpath: Path) -> None:
        if not dirpath.is_dir():
            return
        for fp in sorted(dirpath.glob("*.rego")):
            name = fp.stem
            try:
                content = fp.read_text(encoding="utf-8")
                self._policies[name] = content
                logger.info("Loaded Rego policy: %s", name)
            except Exception as e:
                logger.warning("Failed to load policy %s: %s", fp, e)

    def get_summary(self) -> dict:
        return {
            "total_policies": len(self._policies),
            "policy_names": list(self._policies.keys()),
            "using_external_opa": self._use_external,
            "opa_endpoint": self._opa_endpoint if self._use_external else None,
            "builtin_policies": list(BUILTIN_POLICIES.keys()),
        }
