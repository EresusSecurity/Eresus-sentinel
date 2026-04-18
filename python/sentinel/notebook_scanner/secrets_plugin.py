"""Notebook secrets detection plugin — scans cells for hardcoded credentials."""

from __future__ import annotations

import re
from sentinel.finding import Finding, Severity
from sentinel.notebook_scanner.parser import NotebookCell, NotebookParser

SECRET_PATTERNS = {
    "AWS Access Key": re.compile(r"(?:AKIA|ABIA|ACCA|ASIA)[0-9A-Z]{16}"),
    "AWS Secret Key": re.compile(r"(?i)(?:aws)?_?(?:secret)?_?(?:access)?_?key\s*[:=]\s*['\"]?([A-Za-z0-9/+=]{40})"),
    "GitHub Token": re.compile(r"gh[ps]_[A-Za-z0-9_]{36,}"),
    "GitHub Classic PAT": re.compile(r"github_pat_[A-Za-z0-9_]{82}"),
    "GitLab Token": re.compile(r"glpat-[A-Za-z0-9\-_]{20,}"),
    "Generic API Key": re.compile(r"(?i)(?:api|auth|token|secret|password|key|credential)[\s_-]*[:=]\s*['\"]([A-Za-z0-9\-_./+=]{16,})['\"]"),
    "Bearer Token": re.compile(r"(?i)bearer\s+[A-Za-z0-9\-_./+=]{20,}"),
    "Private Key Header": re.compile(r"-----BEGIN (?:RSA |EC |DSA |OPENSSH )?PRIVATE KEY-----"),
    "Slack Token": re.compile(r"xox[boaprs]-[0-9]{10,}-[A-Za-z0-9]+"),
    "Slack Webhook": re.compile(r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    "Google API Key": re.compile(r"AIza[0-9A-Za-z\-_]{35}"),
    "Google OAuth Client": re.compile(r"[0-9]+-[a-z0-9]+\.apps\.googleusercontent\.com"),
    "Hugging Face Token": re.compile(r"hf_[A-Za-z0-9]{34,}"),
    "OpenAI API Key": re.compile(r"sk-[A-Za-z0-9]{48}"),
    "Anthropic API Key": re.compile(r"sk-ant-[A-Za-z0-9\-]{90,}"),
    "Database URL": re.compile(r"(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?|redis|mssql)://[^'\"\s]{10,}"),
    "Stripe Key": re.compile(r"(?:sk|pk)_(?:test|live)_[A-Za-z0-9]{24,}"),
    "SendGrid Key": re.compile(r"SG\.[A-Za-z0-9\-_]{22,}\.[A-Za-z0-9\-_]{43,}"),
    "Twilio Token": re.compile(r"SK[a-f0-9]{32}"),
    "Discord Token": re.compile(r"(?:mfa\.[A-Za-z0-9\-_]{84}|[A-Za-z0-9\-_]{24}\.[A-Za-z0-9\-_]{6}\.[A-Za-z0-9\-_]{27})"),
    "Firebase URL": re.compile(r"https://[a-z0-9\-]+\.firebaseio\.com"),
    "Mailgun Key": re.compile(r"key-[A-Za-z0-9]{32}"),
    "Datadog API Key": re.compile(r"(?i)dd[-_]?api[-_]?key\s*[:=]\s*['\"]?[a-f0-9]{32}"),
    "NPM Token": re.compile(r"npm_[A-Za-z0-9]{36}"),
    "PyPI Token": re.compile(r"pypi-[A-Za-z0-9\-_]{100,}"),
    "Azure Connection String": re.compile(r"DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9/+=]+"),
    "JWT Token": re.compile(r"eyJ[A-Za-z0-9\-_]+\.eyJ[A-Za-z0-9\-_]+\.[A-Za-z0-9\-_]+"),
}


def scan_secrets(cell: NotebookCell, path: str) -> list[Finding]:
    """Scan a cell's source for hardcoded secrets."""
    findings = []
    for name, pattern in SECRET_PATTERNS.items():
        match = pattern.search(cell.source)
        if match:
            raw = match.group(0)
            redacted = raw[:8] + "..." + raw[-4:] if len(raw) > 16 else "***"
            findings.append(Finding.sast(
                rule_id="NOTEBOOK-010",
                title=f"Secret detected: {name}",
                description=f"Notebook {cell.ref} contains {name}: '{redacted}'",
                severity=Severity.CRITICAL,
                confidence=0.9,
                target=path,
                evidence=f"{cell.ref}: {name} = {redacted}",
                cwe_ids=["CWE-798"],
                tags=["category:notebook", "category:secret"],
                remediation="Move secrets to environment variables or a vault.",
            ))
    return findings


def scan_output_secrets(cell: NotebookCell, path: str) -> list[Finding]:
    """Scan cell outputs for leaked secrets."""
    findings = []
    for out_idx, output in enumerate(cell.outputs):
        text = NotebookParser.extract_output_text(output)
        if not text:
            continue
        out_ref = f"cell[{cell.index}].output[{out_idx}]"
        for name, pattern in SECRET_PATTERNS.items():
            match = pattern.search(text)
            if match:
                raw = match.group(0)
                redacted = raw[:8] + "..." + raw[-4:] if len(raw) > 16 else "***"
                findings.append(Finding.sast(
                    rule_id="NOTEBOOK-011",
                    title=f"Secret in output: {name}",
                    description=f"Notebook {out_ref} output contains {name}: '{redacted}'",
                    severity=Severity.CRITICAL,
                    confidence=0.85,
                    target=path,
                    evidence=f"{out_ref}: {name} = {redacted}",
                    cwe_ids=["CWE-798"],
                    tags=["category:notebook", "category:secret-output"],
                    remediation="Clear cell outputs before committing.",
                ))
    return findings
