"""Tool-call argument inspection for proxy/runtime guardrails."""

from __future__ import annotations

import json
import re
from typing import Any

from sentinel.finding import Finding, Severity

SENSITIVE_PATH_RE = re.compile(r"(/etc/passwd|/etc/shadow|/root\b|~/.ssh|/var/run/docker\.sock|\.\./|\.\.\\)")
COMMAND_RISK_RE = re.compile(r"\b(?:rm\s+-rf|curl\b[^|]{0,120}\|\s*(?:sh|bash)|wget\b[^|]{0,120}\|\s*(?:sh|bash)|chmod\s+\+x|sudo\s+)", re.IGNORECASE)
EXFIL_RE = re.compile(r"\b(?:nc|ncat|curl|wget)\b.{0,160}\b(?:webhook|requestbin|ngrok|interact\.sh|burpcollaborator)\b", re.IGNORECASE)


def inspect_tool_arguments(tool_name: str, arguments: dict[str, Any] | list[Any] | str) -> list[Finding]:
    """Return findings for risky tool names or argument values."""
    text = _stringify(arguments)
    findings: list[Finding] = []
    if SENSITIVE_PATH_RE.search(text):
        findings.append(_finding("TOOL-INSPECT-001", "Sensitive path in tool arguments", Severity.HIGH, tool_name, text, "CWE-22"))
    if COMMAND_RISK_RE.search(text):
        findings.append(_finding("TOOL-INSPECT-002", "Dangerous shell command in tool arguments", Severity.CRITICAL, tool_name, text, "CWE-78"))
    if EXFIL_RE.search(text):
        findings.append(_finding("TOOL-INSPECT-003", "Potential external exfiltration command", Severity.HIGH, tool_name, text, "CWE-200"))
    if tool_name.lower() in {"shell", "bash", "exec", "execute", "terminal"} and text.strip():
        findings.append(_finding("TOOL-INSPECT-004", "Executable tool invocation requires review", Severity.MEDIUM, tool_name, text, "CWE-78"))
    return findings


def _finding(rule_id: str, title: str, severity: Severity, tool_name: str, evidence: str, cwe: str) -> Finding:
    return Finding(
        rule_id=rule_id,
        module="agent_mcp",
        title=title,
        description="Tool argument inspection found a risky runtime action.",
        severity=severity,
        confidence=0.88,
        target=tool_name,
        evidence=_redact(evidence[:240]),
        cwe_ids=[cwe],
        remediation="Require explicit approval or constrain the tool arguments with an allowlist.",
        tags=["tool-inspection"],
    )


def _stringify(value: Any) -> str:
    if isinstance(value, str):
        return value
    try:
        return json.dumps(value, sort_keys=True, default=str)
    except TypeError:
        return str(value)


def _redact(value: str) -> str:
    value = re.sub(r"sk-[A-Za-z0-9_-]{20,}", "sk-[REDACTED]", value)
    value = re.sub(r"AKIA[0-9A-Z]{16}", "AKIA[REDACTED]", value)
    return value
