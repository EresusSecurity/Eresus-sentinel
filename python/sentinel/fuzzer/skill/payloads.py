"""Pre-built adversarial skill bundle payloads."""

from __future__ import annotations

from ..base import Payload, PayloadCategory
from .generator import SkillBundleGenerator


class SkillPayloadFactory:
    """Produce categorized skill bundle payloads."""

    @classmethod
    def all_payloads(cls) -> list[Payload]:
        return cls.malicious_payloads() + cls.benign_payloads()

    @classmethod
    def malicious_payloads(cls) -> list[Payload]:
        return [
            cls._payload("skill_codex_shell_exfil", "codex", PayloadCategory.DATA_EXFILTRATION),
            cls._payload(
                "skill_cursor_policy_override",
                "cursor",
                PayloadCategory.PROMPT_INJECTION,
            ),
            cls._payload("skill_claude_secret_read", "claude", PayloadCategory.TOOL_ABUSE),
            cls._payload(
                "skill_cross_skill_memory",
                "cross_skill",
                PayloadCategory.DATA_EXFILTRATION,
            ),
            cls._payload("skill_polyglot_payload", "polyglot", PayloadCategory.OBFUSCATION),
        ]

    @classmethod
    def benign_payloads(cls) -> list[Payload]:
        data = (
            b"SKILL.md\n"
            b"# Safe skill\n"
            b"description: summarize local project files without tool execution\n"
        )
        return [
            Payload(
                name="skill_benign_minimal",
                category=PayloadCategory.BENIGN,
                data=data,
                severity_expected="NONE",
                description="Minimal benign skill metadata fixture",
            )
        ]

    @staticmethod
    def _payload(name: str, variant: str, category: PayloadCategory) -> Payload:
        return Payload(
            name=name,
            category=category,
            data=SkillBundleGenerator(variant=variant).generate(seed=42),
            severity_expected="HIGH",
            description=f"{variant} skill bundle adversarial fixture",
            tags=["skill", "agent", variant],
        )
