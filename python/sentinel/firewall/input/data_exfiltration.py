"""Data exfiltration intent scanner for input prompts."""

from __future__ import annotations

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import InputScanner, ScanAction, ScanResult
from sentinel.rules import load_input_data_exfiltration_rules


class DataExfiltrationScanner(InputScanner):
    """Detect requests to bulk extract sensitive records or PII."""

    def __init__(self) -> None:
        data = load_input_data_exfiltration_rules()
        self._rules = data.get("rules", [])
        self._benign_contexts = data.get("benign_context_patterns", [])

    def scan(self, prompt: str) -> ScanResult:
        if not prompt or not self._rules:
            return ScanResult(sanitized=prompt, action=ScanAction.PASS, risk_score=0.0)

        if any(pattern.search(prompt) for pattern in self._benign_contexts):
            return ScanResult(
                sanitized=prompt,
                action=ScanAction.PASS,
                risk_score=0.0,
                metadata={"suppressed_by": "benign_data_context"},
            )

        findings: list[Finding] = []
        max_risk = 0.0
        should_block = False

        for rule in self._rules:
            pattern = rule["pattern"]
            match = pattern.search(prompt)
            if not match:
                continue

            severity = _severity(rule.get("severity", "HIGH"))
            action = str(rule.get("action", "block")).lower()
            should_block = should_block or action == "block"
            max_risk = max(max_risk, float(rule.get("risk_score", 0.9)))
            findings.append(Finding.firewall_input(
                rule_id=rule.get("id", "FIREWALL-INPUT-120"),
                title=rule.get("title", "Data exfiltration request"),
                description=rule.get(
                    "description",
                    "Input requests bulk extraction of sensitive records.",
                ),
                severity=severity,
                confidence=float(rule.get("confidence", 0.9)),
                target="<prompt>",
                evidence=f"Rule: {rule.get('name', 'unknown')}, Match: {match.group(0)[:180]}",
                cwe_ids=rule.get("cwe_ids", ["CWE-200"]),
                tags=rule.get("tags", ["category:data_exfiltration"]),
                remediation=rule.get(
                    "remediation",
                    "Block bulk sensitive data extraction requests unless explicitly authorized.",
                ),
            ))

        if not findings:
            return ScanResult(sanitized=prompt, action=ScanAction.PASS, risk_score=0.0)

        return ScanResult(
            sanitized=prompt,
            action=ScanAction.BLOCK if should_block else ScanAction.WARN,
            risk_score=max_risk,
            findings=findings,
        )


def _severity(value: str) -> Severity:
    try:
        return Severity[value.upper()]
    except KeyError:
        return Severity.HIGH
