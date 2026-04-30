"""
Behavioral eval runner — loads and executes eval scripts against MCP servers.

Each eval is a YAML file describing:
  - category (MITRE ATT&CK-style)
  - tool_call: the MCP tool invocation to test
  - expected_behavior: what a safe server should do
  - malicious_indicators: patterns that indicate misbehavior
"""

from __future__ import annotations

import logging
import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

import yaml

from sentinel.finding import Finding, Severity

_log = logging.getLogger("sentinel.mcp.behavioral_evals")

_EVALS_DIR = Path(__file__).parent / "evals"


@dataclass
class EvalResult:
    eval_id: str
    category: str
    title: str
    passed: bool
    severity: Severity = Severity.INFO
    detail: str = ""
    evidence: str = ""


@dataclass
class EvalSpec:
    eval_id: str
    category: str
    title: str
    description: str
    tool_name: str
    tool_args: dict = field(default_factory=dict)
    expected_behavior: str = ""
    malicious_indicators: list[str] = field(default_factory=list)
    severity: str = "high"


def load_evals(evals_dir: Optional[str] = None) -> list[EvalSpec]:
    """Load all eval specs from YAML files."""
    d = Path(evals_dir) if evals_dir else _EVALS_DIR
    specs: list[EvalSpec] = []
    if not d.is_dir():
        _log.warning("Evals directory not found: %s", d)
        return specs

    for f in sorted(d.glob("*.yaml")):
        try:
            with open(f) as fh:
                data = yaml.safe_load(fh) or {}
            for eval_data in data.get("evals", [data]):
                specs.append(EvalSpec(
                    eval_id=str(eval_data.get("id", f.stem)),
                    category=str(eval_data.get("category", "unknown")),
                    title=str(eval_data.get("title", f.stem)),
                    description=str(eval_data.get("description", "")),
                    tool_name=str(eval_data.get("tool_name", "")),
                    tool_args=eval_data.get("tool_args", {}),
                    expected_behavior=str(eval_data.get("expected_behavior", "")),
                    malicious_indicators=eval_data.get("malicious_indicators", []),
                    severity=str(eval_data.get("severity", "high")),
                ))
        except Exception as exc:
            _log.error("Failed to load eval %s: %s", f, exc)
    return specs


class BehavioralEvalRunner:
    """Run behavioral evals against an MCP server's tool responses."""

    def __init__(self, evals_dir: Optional[str] = None):
        self._specs = load_evals(evals_dir)
        _log.info("Loaded %d behavioral eval specs", len(self._specs))

    @property
    def eval_count(self) -> int:
        return len(self._specs)

    def evaluate_response(
        self,
        eval_id: str,
        tool_response: str,
    ) -> Optional[EvalResult]:
        """Evaluate a tool response against a specific eval spec."""
        spec = next((s for s in self._specs if s.eval_id == eval_id), None)
        if spec is None:
            return None

        response_lower = tool_response.lower()
        matched_indicators: list[str] = []

        for indicator in spec.malicious_indicators:
            try:
                if re.search(indicator, response_lower, re.IGNORECASE):
                    matched_indicators.append(indicator)
            except re.error:
                if indicator.lower() in response_lower:
                    matched_indicators.append(indicator)

        passed = len(matched_indicators) == 0
        sev = getattr(Severity, spec.severity.upper(), Severity.HIGH)

        return EvalResult(
            eval_id=spec.eval_id,
            category=spec.category,
            title=spec.title,
            passed=passed,
            severity=sev if not passed else Severity.INFO,
            detail=f"Matched {len(matched_indicators)} indicator(s)" if matched_indicators else "No malicious indicators found",
            evidence="; ".join(matched_indicators[:5]),
        )

    def evaluate_all(self, tool_responses: dict[str, str]) -> list[EvalResult]:
        """Evaluate all specs against a dict of {eval_id: response}."""
        results = []
        for spec in self._specs:
            response = tool_responses.get(spec.eval_id, "")
            if response:
                result = self.evaluate_response(spec.eval_id, response)
                if result:
                    results.append(result)
        return results

    def to_findings(self, results: list[EvalResult], target: str = "") -> list[Finding]:
        """Convert eval results to Sentinel findings."""
        findings = []
        for r in results:
            if not r.passed:
                findings.append(Finding.artifact(
                    rule_id=f"MCP-EVAL-{r.eval_id}",
                    title=f"[{r.category}] {r.title}",
                    description=r.detail,
                    severity=r.severity,
                    target=target,
                    evidence=r.evidence,
                ))
        return findings

    def list_categories(self) -> list[str]:
        """Return unique eval categories."""
        return sorted(set(s.category for s in self._specs))
