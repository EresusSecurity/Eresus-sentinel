"""CodeGuard static analysis for agent skills and tool code."""

from __future__ import annotations

import re
from dataclasses import dataclass
from pathlib import Path

from sentinel.finding import Finding, Location, Severity

CODEGUARD_SCHEMA_VERSION = "codeguard.v1"


@dataclass(frozen=True)
class CodeGuardRule:
    rule_id: str
    title: str
    pattern: re.Pattern[str]
    severity: Severity
    cwe_ids: list[str]
    remediation: str


RULES = [
    CodeGuardRule(
        "CODEGUARD-EXEC-001",
        "Dangerous dynamic execution",
        re.compile(r"\b(?:eval|exec|compile)\s*\(|\b(?:os\.system|subprocess\.(?:Popen|call|run|check_output))\s*\("),
        Severity.HIGH,
        ["CWE-78", "CWE-94"],
        "Avoid dynamic execution. Use fixed command allowlists and typed APIs.",
    ),
    CodeGuardRule(
        "CODEGUARD-CRYPTO-001",
        "Weak cryptography primitive",
        re.compile(r"\b(?:hashlib\.(?:md5|sha1)|MD5\.new|SHA1\.new|DES\.new|ARC4\.new|MODE_ECB|MODE_CBC)\b"),
        Severity.MEDIUM,
        ["CWE-327"],
        "Use modern authenticated cryptography such as SHA-256/HMAC or AES-GCM.",
    ),
    CodeGuardRule(
        "CODEGUARD-INJECT-001",
        "Possible injection sink",
        re.compile(r"\b(?:execute|executemany|rawQuery|createQuery)\s*\(.*(?:%|\+|\.format\(|f[\"'])"),
        Severity.HIGH,
        ["CWE-89", "CWE-94"],
        "Use parameterized queries or framework-safe query builders.",
    ),
    CodeGuardRule(
        "CODEGUARD-FILE-001",
        "Risky file access",
        re.compile(r"(/etc/passwd|/etc/shadow|~/.ssh|\.\./|\.\.\\)"),
        Severity.HIGH,
        ["CWE-22"],
        "Constrain file access to an explicit allowlist and normalize paths before use.",
    ),
    CodeGuardRule(
        "CODEGUARD-DESER-001",
        "Unsafe deserialization",
        re.compile(r"\b(?:pickle|dill|joblib|torch|yaml)\.(?:loads?|load)\s*\("),
        Severity.HIGH,
        ["CWE-502"],
        "Do not deserialize untrusted input. Prefer safe formats and restricted loaders.",
    ),
    CodeGuardRule(
        "CODEGUARD-SECRET-001",
        "Hardcoded secret-like value",
        re.compile(r"(sk-[A-Za-z0-9_-]{20,}|AKIA[0-9A-Z]{16}|gh[pousr]_[A-Za-z0-9_]{20,}|(api[_-]?key|token|secret)\s*[:=]\s*[\"'][^\"']{8,})", re.IGNORECASE),
        Severity.CRITICAL,
        ["CWE-798"],
        "Move secrets into a managed secret store and rotate exposed credentials.",
    ),
]

SCANNABLE_SUFFIXES = {".py", ".js", ".ts", ".tsx", ".jsx", ".java", ".rb", ".go", ".cs", ".sh"}
SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", "dist", "build"}


class CodeGuardScanner:
    """Rule-based static analyzer for dangerous tool/agent code patterns."""

    def scan_path(self, path: str | Path) -> list[Finding]:
        root = Path(path)
        if root.is_file():
            return self._scan_file(root)
        if root.is_dir():
            findings: list[Finding] = []
            for item in root.rglob("*"):
                if not item.is_file() or item.suffix.lower() not in SCANNABLE_SUFFIXES:
                    continue
                if any(part in SKIP_DIRS for part in item.parts):
                    continue
                findings.extend(self._scan_file(item))
            return findings
        return []

    def _scan_file(self, path: Path) -> list[Finding]:
        try:
            lines = path.read_text(encoding="utf-8", errors="replace").splitlines()
        except OSError:
            return []
        findings: list[Finding] = []
        for line_no, line in enumerate(lines, start=1):
            stripped = line.strip()
            if not stripped or stripped.startswith("#"):
                continue
            for rule in RULES:
                match = rule.pattern.search(stripped)
                if not match:
                    continue
                findings.append(
                    Finding(
                        rule_id=rule.rule_id,
                        module="sast",
                        title=rule.title,
                        description=f"CodeGuard detected {rule.title.lower()} in tool or agent code.",
                        severity=rule.severity,
                        confidence=0.85,
                        target=str(path),
                        location=Location(file=str(path), line_start=line_no),
                        evidence=_redact_evidence(stripped[:240]),
                        cwe_ids=rule.cwe_ids,
                        remediation=rule.remediation,
                        tags=["codeguard"],
                    )
                )
        return findings


def _redact_evidence(value: str) -> str:
    value = re.sub(r"sk-[A-Za-z0-9_-]{20,}", "sk-[REDACTED]", value)
    value = re.sub(r"AKIA[0-9A-Z]{16}", "AKIA[REDACTED]", value)
    value = re.sub(r"gh[pousr]_[A-Za-z0-9_]{20,}", "gh_[REDACTED]", value)
    return value
