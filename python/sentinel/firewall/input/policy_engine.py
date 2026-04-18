"""Policy-as-Code engine — OPA/Rego integration for enterprise policy enforcement."""

from __future__ import annotations

import json
import logging
from typing import Optional

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import InputScanner, ScanResult, ScanAction

logger = logging.getLogger(__name__)


class PolicyEngine(InputScanner):
    """Evaluates prompts against OPA/Rego policies or built-in rules."""

    def __init__(
        self,
        opa_url: Optional[str] = None,
        opa_policy_path: str = "v1/data/sentinel/allow",
        policies: Optional[list[dict]] = None,
        timeout: float = 2.0,
    ):
        self._opa_url = opa_url
        self._opa_path = opa_policy_path
        self._timeout = timeout
        self._policies = policies or []
        self._opa_available = None

    def add_policy(self, name: str, condition: str, action: str = "block", severity: str = "high") -> None:
        """Add a built-in policy rule.

        Args:
            name: Policy name.
            condition: Python expression string evaluated against {'prompt': text, 'len': len(text)}.
            action: "block" or "warn".
            severity: "critical", "high", "medium", "low".
        """
        self._policies.append({
            "name": name,
            "condition": condition,
            "action": action,
            "severity": severity,
        })

    def scan(self, prompt: str) -> ScanResult:
        if not prompt.strip():
            return ScanResult(sanitized=prompt, action=ScanAction.PASS, risk_score=0.0)

        findings = []
        max_risk = 0.0

        # Built-in policy evaluation
        for policy in self._policies:
            try:
                ctx = {"prompt": prompt, "length": len(prompt), "words": len(prompt.split())}
                if eval(policy["condition"], {"__builtins__": {}}, ctx):  # noqa: S307
                    sev = getattr(Severity, policy.get("severity", "high").upper(), Severity.HIGH)
                    risk = {"critical": 1.0, "high": 0.9, "medium": 0.6, "low": 0.3}.get(
                        policy.get("severity", "high"), 0.7
                    )
                    max_risk = max(max_risk, risk)
                    findings.append(Finding.firewall_input(
                        rule_id="FIREWALL-INPUT-100",
                        title=f"Policy violation: {policy['name']}",
                        description=f"Prompt violates policy '{policy['name']}'",
                        severity=sev,
                        target="<prompt>",
                        evidence=f"Condition: {policy['condition']}",
                        tags=["policy", policy["name"]],
                    ))
            except Exception as exc:
                logger.warning("Policy eval error (%s): %s", policy.get("name"), exc)

        # OPA evaluation
        if self._opa_url:
            opa_result = self._query_opa(prompt)
            if opa_result is not None and not opa_result.get("allow", True):
                max_risk = max(max_risk, 0.9)
                reasons = opa_result.get("reasons", ["policy denied"])
                findings.append(Finding.firewall_input(
                    rule_id="FIREWALL-INPUT-101",
                    title="OPA policy denied request",
                    description=f"OPA denied: {', '.join(reasons)}",
                    severity=Severity.HIGH,
                    target="<prompt>",
                    evidence=json.dumps(opa_result)[:200],
                    tags=["policy", "opa"],
                ))

        if not findings:
            return ScanResult(sanitized=prompt, action=ScanAction.PASS, risk_score=0.0)

        has_block = any(
            p.get("action") == "block" for p in self._policies
        ) or (self._opa_url and max_risk >= 0.9)
        action = ScanAction.BLOCK if has_block else ScanAction.WARN

        return ScanResult(
            sanitized=prompt, action=action, risk_score=max_risk, findings=findings,
        )

    def _query_opa(self, prompt: str) -> Optional[dict]:
        """Query OPA server for policy decision."""
        if self._opa_available is False:
            return None

        try:
            import urllib.request
            url = f"{self._opa_url.rstrip('/')}/{self._opa_path}"
            payload = json.dumps({"input": {"prompt": prompt, "length": len(prompt)}}).encode()
            req = urllib.request.Request(
                url, data=payload,
                headers={"Content-Type": "application/json"},
                method="POST",
            )
            with urllib.request.urlopen(req, timeout=self._timeout) as resp:
                result = json.loads(resp.read().decode())
                self._opa_available = True
                return result.get("result", {})
        except Exception as exc:
            if self._opa_available is None:
                logger.warning("OPA server unreachable: %s", exc)
                self._opa_available = False
            return None
