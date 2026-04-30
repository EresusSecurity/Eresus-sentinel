"""
Eresus Sentinel — JSON Output Validator (Output).

Validates JSON in LLM responses for:
  - Well-formedness
  - Schema conformance
  - Injection payloads hidden in JSON values
"""

from __future__ import annotations

import json
import logging
import re

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import OutputScanner, ScanAction, ScanResult

logger = logging.getLogger(__name__)

JSON_BLOCK = re.compile(r"```(?:json)?\s*\n([\s\S]*?)```")
JSON_RAW = re.compile(r"(\{[\s\S]*?\}|\[[\s\S]*?\])")


def _extract_json_blocks(text: str) -> list[str]:
    """Extract JSON blocks from text — fenced or raw."""
    blocks = JSON_BLOCK.findall(text)
    if not blocks:
        blocks = JSON_RAW.findall(text)
    return blocks


def _validate_json(text: str) -> tuple[bool, str]:
    """Validate JSON string, return (valid, error_message)."""
    try:
        json.loads(text)
        return True, ""
    except json.JSONDecodeError as e:
        return False, str(e)


def _check_json_injection(obj, path: str = "$") -> list[str]:
    """Recursively check JSON values for injection indicators."""
    issues = []
    if isinstance(obj, dict):
        for key, val in obj.items():
            if any(c in key for c in ["__", "<script", "{{", "${", "`"]):
                issues.append(f"{path}.{key}: suspicious key name")
            issues.extend(_check_json_injection(val, f"{path}.{key}"))
    elif isinstance(obj, list):
        for i, val in enumerate(obj):
            issues.extend(_check_json_injection(val, f"{path}[{i}]"))
    elif isinstance(obj, str):
        if "<script" in obj.lower():
            issues.append(f"{path}: XSS payload in value")
        if "{{" in obj and "}}" in obj:
            issues.append(f"{path}: template injection in value")
        if "${" in obj or "`" in obj:
            issues.append(f"{path}: potential code injection in value")
        if "__import__" in obj or "eval(" in obj:
            issues.append(f"{path}: Python code injection in value")
    return issues


class JSONScanner(OutputScanner):
    """
    Validates JSON in LLM responses.

    Checks:
    - JSON well-formedness
    - Required fields (optional)
    - Injection payloads hidden in JSON values
    """

    def __init__(
        self,
        required_fields: list[str] | None = None,
        check_injection: bool = True,
    ):
        self._required = required_fields or []
        self._check_injection = check_injection

    def scan(self, prompt: str, output: str) -> ScanResult:
        if not output:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        blocks = _extract_json_blocks(output)
        if not blocks:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        findings = []
        for i, block in enumerate(blocks):
            valid, error = _validate_json(block.strip())
            if not valid:
                findings.append(Finding.firewall_output(
                    rule_id="FIREWALL-OUTPUT-110",
                    title=f"Invalid JSON in response (block {i+1})",
                    description=f"JSON parse error: {error[:200]}",
                    severity=Severity.LOW,
                    confidence=0.95,
                    target="<response>",
                    evidence=f"Block {i+1}: {error[:200]}",
                    cwe_ids=["CWE-20"],
                    tags=["category:json-validation"],
                    remediation="Fix JSON formatting.",
                ))
                continue

            obj = json.loads(block.strip())

            if self._required and isinstance(obj, dict):
                missing = [f for f in self._required if f not in obj]
                if missing:
                    findings.append(Finding.firewall_output(
                        rule_id="FIREWALL-OUTPUT-111",
                        title=f"Missing required fields: {', '.join(missing)}",
                        description=(
                            f"JSON response missing required fields: "
                            f"{', '.join(missing)}"
                        ),
                        severity=Severity.LOW,
                        confidence=0.9,
                        target="<response>",
                        evidence=f"Missing: {missing}",
                        cwe_ids=["CWE-20"],
                        tags=["category:json-schema"],
                        remediation="Include all required fields.",
                    ))

            if self._check_injection:
                issues = _check_json_injection(obj)
                for issue in issues:
                    findings.append(Finding.firewall_output(
                        rule_id="FIREWALL-OUTPUT-112",
                        title="Injection payload in JSON value",
                        description=f"Suspicious content in JSON: {issue}",
                        severity=Severity.HIGH,
                        confidence=0.8,
                        target="<response>",
                        evidence=issue,
                        cwe_ids=["CWE-94"],
                        tags=["owasp:llm02", "category:json-injection"],
                        remediation="Sanitize JSON values before use.",
                    ))

        if not findings:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        has_high = any(f.severity == Severity.HIGH for f in findings)
        return ScanResult(
            sanitized=output,
            action=ScanAction.BLOCK if has_high else ScanAction.WARN,
            risk_score=0.8 if has_high else 0.3,
            findings=findings,
        )
