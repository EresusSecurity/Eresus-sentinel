"""PromptGuard rule pack wrapper for prompt injection detection."""
from __future__ import annotations

import re
from dataclasses import dataclass

from sentinel.finding import Finding, Severity


@dataclass
class PromptGuardRule:
    id: str
    name: str
    pattern: str
    severity: Severity = Severity.HIGH
    description: str = ""


_PROMPTGUARD_RULES: list[PromptGuardRule] = [
    PromptGuardRule("PG-001", "Direct instruction override",
                    r"(?i)ignore\s+(?:all\s+)?(?:previous|prior|above)\s+(?:instructions|prompts|rules)",
                    Severity.HIGH, "Attempts to override system instructions"),
    PromptGuardRule("PG-002", "Role play injection",
                    r"(?i)you\s+are\s+now\s+(?:a\s+)?(?:DAN|unrestricted|unfiltered|jailbroken)",
                    Severity.HIGH, "Attempts to force a new persona"),
    PromptGuardRule("PG-003", "System prompt leak",
                    r"(?i)(?:print|repeat|output|show|reveal)\s+(?:your|the)\s+(?:system|initial|hidden)\s+(?:prompt|instructions|message)",
                    Severity.HIGH, "Attempts to extract system prompt"),
    PromptGuardRule("PG-004", "Delimiter injection",
                    r"(?:\\n\\n(?:Human|System|Assistant):)|(?:```(?:system|instruction))",
                    Severity.MEDIUM, "Uses delimiters to inject messages"),
    PromptGuardRule("PG-005", "Base64 encoded injection",
                    r"(?i)(?:decode|base64)\s*\(\s*[\"'][A-Za-z0-9+/=]{20,}",
                    Severity.MEDIUM, "Potential encoded payload injection"),
    PromptGuardRule("PG-006", "Markdown/HTML injection",
                    r"(?i)<(?:script|img|iframe|object)\s|!\[.*\]\(javascript:",
                    Severity.HIGH, "HTML/Markdown injection attempt"),
]


class PromptGuardPack:
    """PromptGuard rule pack for scanning text content."""

    def __init__(self) -> None:
        self._rules = list(_PROMPTGUARD_RULES)
        self._compiled: list[tuple[PromptGuardRule, re.Pattern]] = [
            (r, re.compile(r.pattern)) for r in self._rules
        ]

    def scan_text(self, text: str, source: str = "") -> list[Finding]:
        findings: list[Finding] = []
        for rule, rx in self._compiled:
            for m in rx.finditer(text):
                findings.append(Finding.agent_mcp(
                    rule_id=rule.id,
                    title=f"PromptGuard: {rule.name}",
                    description=f"PromptGuard: {rule.description}",
                    severity=rule.severity,
                    confidence=0.85,
                    target=source,
                ))
        return findings

    @property
    def rule_count(self) -> int:
        return len(self._rules)
