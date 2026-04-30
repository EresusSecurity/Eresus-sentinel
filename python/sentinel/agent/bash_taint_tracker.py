"""Bash/shell script taint analysis for AI skill security scanning.

Detects command injection sinks that receive tainted (unquoted or externally
sourced) data in shell scripts used by AI skills.
"""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

_INJECTION_SINKS = [
    "eval", "exec", "bash", "sh", "zsh", "ksh",
    "source", ".", "chmod", "chown", "curl", "wget",
    "python", "python3", "node", "ruby", "perl",
    "mysql", "psql", "sqlite3",
    "ssh", "scp", "rsync", "nc", "ncat", "netcat",
    "dd", "mkfs", "fdisk", "mount", "umount",
    "sudo", "su", "doas", "pkexec",
]

_UNQUOTED_VAR = re.compile(r'(?<!["\'])(\$[A-Za-z_][A-Za-z0-9_]*|\$\{[^}]+\})(?!["\'])')
_COMMAND_INJECTION_PATTERNS = [
    re.compile(r'\$\(.*\$[A-Za-z_]', re.DOTALL),
    re.compile(r'`[^`]*\$[A-Za-z_][^`]*`'),
    re.compile(r'(?:eval|exec)\s+["\']?\$'),
    re.compile(r'(?:bash|sh)\s+-c\s+["\']?\$'),
]
_EXTERNAL_INPUT = re.compile(
    r'\b(?:read\s+-[rp]?\s*(\w+)|(\w+)=\$\{?\d+\}?|(\w+)=\$\{?@\}?|(\w+)=\$\{?\*\}?)',
    re.IGNORECASE,
)


@dataclass
class TaintIssue:
    line_no: int
    line: str
    pattern: str
    severity: str
    description: str


@dataclass
class BashTaintResult:
    source: str
    issues: list[TaintIssue] = field(default_factory=list)
    tainted_vars: list[str] = field(default_factory=list)
    error: Optional[str] = None

    @property
    def risk_score(self) -> float:
        weights = {"CRITICAL": 0.4, "HIGH": 0.25, "MEDIUM": 0.1}
        return min(1.0, sum(weights.get(i.severity, 0.05) for i in self.issues))


class BashTaintTracker:
    """Detect taint flow from external inputs to dangerous sinks in shell scripts."""

    def analyze_file(self, path: str) -> BashTaintResult:
        p = Path(path)
        if not p.exists():
            return BashTaintResult(source=path, error=f"File not found: {path}")
        try:
            return self.analyze_script(p.read_text(errors="ignore"), path)
        except Exception as exc:
            return BashTaintResult(source=path, error=str(exc))

    def analyze_script(self, script: str, name: str = "<script>") -> BashTaintResult:
        result = BashTaintResult(source=name)
        lines = script.splitlines()

        tainted: set[str] = set()
        for i, line in enumerate(lines, start=1):
            stripped = line.strip()
            if stripped.startswith("#") or not stripped:
                continue

            m = _EXTERNAL_INPUT.search(line)
            if m:
                var = next((g for g in m.groups() if g), None)
                if var:
                    tainted.add(var)
                    result.tainted_vars.append(var)

            for pat in _COMMAND_INJECTION_PATTERNS:
                if pat.search(line):
                    result.issues.append(TaintIssue(
                        line_no=i,
                        line=line.rstrip(),
                        pattern=pat.pattern,
                        severity="HIGH",
                        description="Command substitution with tainted variable",
                    ))

            unquoted_vars = _UNQUOTED_VAR.findall(line)
            for var_ref in unquoted_vars:
                var_name = var_ref.lstrip("$").strip("{}")
                if var_name in tainted:
                    result.issues.append(TaintIssue(
                        line_no=i,
                        line=line.rstrip(),
                        pattern="unquoted_tainted_var",
                        severity="MEDIUM",
                        description=f"Unquoted tainted variable {var_ref!r} may cause word splitting or injection",
                    ))

            for sink in _INJECTION_SINKS:
                sink_pattern = re.compile(
                    r'(?:^|[\s;|&(])' + re.escape(sink) + r'(?:\s|\Z)',
                )
                if sink_pattern.search(line):
                    taint_refs = _UNQUOTED_VAR.findall(line)
                    if taint_refs:
                        result.issues.append(TaintIssue(
                            line_no=i,
                            line=line.rstrip(),
                            pattern=f"sink:{sink}",
                            severity=_sink_severity(sink),
                            description=f"Dangerous sink '{sink}' used with unquoted variable(s): {taint_refs}",
                        ))

        return result


def _sink_severity(sink: str) -> str:
    critical = {"eval", "exec", "bash", "sh", "sudo", "su"}
    high = {"python", "python3", "node", "ruby", "perl", "curl", "wget", "ssh"}
    if sink in critical:
        return "CRITICAL"
    if sink in high:
        return "HIGH"
    return "MEDIUM"
