"""Shell command safety policy and classifier for agent skill scanning."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from sentinel.finding import Finding, Severity


class CommandRisk(str, Enum):
    SAFE = "safe"
    CAUTION = "caution"
    DANGEROUS = "dangerous"
    BLOCKED = "blocked"


_DANGEROUS_COMMANDS = frozenset({
    "rm -rf", "rm -r /", "mkfs", "dd if=", ":(){", "fork bomb",
    "chmod -R 777", "curl | sh", "curl | bash", "wget | sh",
    "eval(", "exec(", "os.system(", "subprocess.call(",
    "> /dev/sda", "shutdown", "reboot", "halt",
})

_CAUTION_COMMANDS = frozenset({
    "chmod", "chown", "kill", "pkill", "pip install",
    "npm install -g", "apt install", "brew install",
    "docker run", "kubectl delete", "terraform destroy",
    "git push --force", "git reset --hard",
})

_SAFE_PATTERNS = frozenset({
    "ls", "cat", "echo", "pwd", "date", "whoami",
    "head", "tail", "grep", "find", "wc", "sort",
    "git status", "git log", "git diff", "git branch",
    "python --version", "node --version", "npm --version",
})


@dataclass
class CommandClassification:
    command: str
    risk: CommandRisk
    reason: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


def classify_command(command: str) -> CommandClassification:
    """Classify a shell command by risk level."""
    cmd_lower = command.strip().lower()

    for pattern in _DANGEROUS_COMMANDS:
        if pattern in cmd_lower:
            return CommandClassification(command, CommandRisk.DANGEROUS,
                                         f"Matches dangerous pattern: {pattern}")

    for pattern in _CAUTION_COMMANDS:
        if pattern in cmd_lower:
            return CommandClassification(command, CommandRisk.CAUTION,
                                         f"Matches caution pattern: {pattern}")

    for pattern in _SAFE_PATTERNS:
        if cmd_lower.startswith(pattern):
            return CommandClassification(command, CommandRisk.SAFE, "Known safe command")

    return CommandClassification(command, CommandRisk.CAUTION, "Unknown command — review needed")


def scan_code_for_commands(text: str, filepath: str = "") -> list[Finding]:
    """Scan code for shell command invocations and classify them."""
    findings: list[Finding] = []
    patterns = [
        (re.compile(r"""os\.system\s*\(\s*["']([^"']+)["']"""), "os.system"),
        (re.compile(r"""subprocess\.(?:run|call|Popen)\s*\(\s*["']([^"']+)["']"""), "subprocess"),
        (re.compile(r"""subprocess\.(?:run|call|Popen)\s*\(\s*\[["']([^"']+)["']"""), "subprocess-list"),
    ]

    for rx, source in patterns:
        for m in rx.finditer(text):
            cmd = m.group(1)
            classification = classify_command(cmd)
            if classification.risk in (CommandRisk.DANGEROUS, CommandRisk.BLOCKED):
                findings.append(Finding.agent_mcp(
                    rule_id="SKILL-CMD-001",
                    title="Dangerous command in skill",
                    description=f"Dangerous command in skill: {cmd[:100]}",
                    severity=Severity.HIGH,
                    confidence=0.85,
                    target=filepath,
                ))
            elif classification.risk == CommandRisk.CAUTION:
                findings.append(Finding.agent_mcp(
                    rule_id="SKILL-CMD-002",
                    title="Caution-level command",
                    description=f"Caution-level command in skill: {cmd[:100]}",
                    severity=Severity.MEDIUM,
                    confidence=0.6,
                    target=filepath,
                ))

    return findings
