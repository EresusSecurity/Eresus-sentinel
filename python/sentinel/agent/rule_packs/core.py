"""Core detection rule pack for AI skill scanning."""
from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Callable, Optional


@dataclass
class Rule:
    """A single detection rule."""
    id: str
    name: str
    severity: str
    description: str
    pattern: Optional[re.Pattern] = None
    check_fn: Optional[Callable[[str], bool]] = None
    tags: list[str] = field(default_factory=list)

    def matches(self, text: str) -> bool:
        if self.pattern is not None and self.pattern.search(text):
            return True
        if self.check_fn is not None and self.check_fn(text):
            return True
        return False


@dataclass
class RuleMatchResult:
    rule: Rule
    matched_text: str
    offset: int = 0


class RulePack:
    """A named collection of detection rules."""

    def __init__(self, name: str, rules: list[Rule]) -> None:
        self.name = name
        self._rules = rules

    @property
    def rules(self) -> list[Rule]:
        return list(self._rules)

    def scan(self, text: str) -> list[RuleMatchResult]:
        results: list[RuleMatchResult] = []
        for rule in self._rules:
            if rule.pattern:
                for m in rule.pattern.finditer(text):
                    results.append(RuleMatchResult(
                        rule=rule,
                        matched_text=m.group(0),
                        offset=m.start(),
                    ))
            elif rule.check_fn and rule.check_fn(text):
                results.append(RuleMatchResult(
                    rule=rule,
                    matched_text="<custom check>",
                ))
        return results


class RulePackRegistry:
    """Registry of available rule packs."""

    _packs: dict[str, RulePack] = {}

    @classmethod
    def register(cls, pack: RulePack) -> None:
        cls._packs[pack.name] = pack

    @classmethod
    def get(cls, name: str) -> Optional[RulePack]:
        return cls._packs.get(name)

    @classmethod
    def all_packs(cls) -> list[RulePack]:
        return list(cls._packs.values())


_CORE_RULES = [
    Rule(
        id="SKILL-001",
        name="eval_usage",
        severity="HIGH",
        description="Use of eval() with dynamic input",
        pattern=re.compile(r'\beval\s*\(', re.IGNORECASE),
        tags=["code_execution", "dynamic"],
    ),
    Rule(
        id="SKILL-002",
        name="exec_usage",
        severity="HIGH",
        description="Use of exec() with dynamic input",
        pattern=re.compile(r'\bexec\s*\(', re.IGNORECASE),
        tags=["code_execution", "dynamic"],
    ),
    Rule(
        id="SKILL-003",
        name="subprocess_shell",
        severity="HIGH",
        description="subprocess called with shell=True",
        pattern=re.compile(r'subprocess\.\w+\s*\(.*shell\s*=\s*True', re.DOTALL),
        tags=["code_execution", "subprocess"],
    ),
    Rule(
        id="SKILL-004",
        name="hardcoded_secret",
        severity="CRITICAL",
        description="Hardcoded API key, token, or password",
        pattern=re.compile(
            r'(?:api_key|secret|password|token|passwd|private_key)\s*=\s*["\'][A-Za-z0-9+/=_\-]{16,}["\']',
            re.IGNORECASE,
        ),
        tags=["secrets", "credentials"],
    ),
    Rule(
        id="SKILL-005",
        name="network_exfil",
        severity="HIGH",
        description="Outbound network call (possible data exfiltration)",
        pattern=re.compile(
            r'(?:requests\.|httpx\.|urllib\.request\.|socket\.connect)\s*\(',
            re.IGNORECASE,
        ),
        tags=["network", "exfiltration"],
    ),
    Rule(
        id="SKILL-006",
        name="pickle_load",
        severity="HIGH",
        description="Unsafe pickle deserialization",
        pattern=re.compile(r'pickle\.loads?\s*\(', re.IGNORECASE),
        tags=["deserialization", "rce"],
    ),
    Rule(
        id="SKILL-007",
        name="yaml_unsafe_load",
        severity="HIGH",
        description="Unsafe yaml.load() call (use yaml.safe_load)",
        pattern=re.compile(r'yaml\.load\s*\([^)]*\)', re.IGNORECASE),
        tags=["deserialization"],
    ),
    Rule(
        id="SKILL-008",
        name="base64_exec_chain",
        severity="CRITICAL",
        description="Base64 decode followed by code execution (common obfuscation pattern)",
        pattern=re.compile(
            r'(?:base64\.b64decode|b64decode)\s*\(.*?(?:exec|eval)\s*\(',
            re.DOTALL | re.IGNORECASE,
        ),
        tags=["obfuscation", "code_execution"],
    ),
    Rule(
        id="SKILL-009",
        name="os_environ_access",
        severity="MEDIUM",
        description="Reading environment variables (potential credential access)",
        pattern=re.compile(r'os\.environ(?:\.get)?\s*\[', re.IGNORECASE),
        tags=["credentials", "environment"],
    ),
    Rule(
        id="SKILL-010",
        name="file_write_arbitrary",
        severity="MEDIUM",
        description="Writing to potentially arbitrary file paths",
        pattern=re.compile(
            r'open\s*\(\s*(?:[^,)]+,\s*)?["\']w["\']',
            re.IGNORECASE,
        ),
        tags=["filesystem", "write"],
    ),
]

CoreRulePack = RulePack(name="core", rules=_CORE_RULES)
RulePackRegistry.register(CoreRulePack)
