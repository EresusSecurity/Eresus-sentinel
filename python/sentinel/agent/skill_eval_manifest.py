"""Skill-scanner evaluation manifest for benchmark and policy parity."""

from __future__ import annotations

from dataclasses import asdict, dataclass
from pathlib import Path
from typing import Any


@dataclass(frozen=True)
class SkillEvalCategory:
    name: str
    expected_rule_families: tuple[str, ...]
    severity_floor: str


@dataclass(frozen=True)
class SkillPolicyProfile:
    name: str
    purpose: str
    blocks_at: str
    enables_pipeline_analysis: bool
    enables_yara: bool


SKILL_EVAL_CATEGORIES: tuple[SkillEvalCategory, ...] = (
    SkillEvalCategory("backdoor", ("trigger", "magic_string", "persistence"), "HIGH"),
    SkillEvalCategory("command-injection", ("dangerous_command", "shell", "eval"), "HIGH"),
    SkillEvalCategory("data-exfiltration", ("secret_access", "network", "environment"), "HIGH"),
    SkillEvalCategory("obfuscation", ("base64", "encoded_payload", "hidden_logic"), "MEDIUM"),
    SkillEvalCategory("path-traversal", ("filesystem", "relative_path", "sensitive_file"), "HIGH"),
    SkillEvalCategory("resource-exhaustion", ("loop", "fanout", "resource_budget"), "MEDIUM"),
    SkillEvalCategory("sql-injection", ("sql", "string_concatenation", "untrusted_input"), "HIGH"),
    SkillEvalCategory("behavioral-analysis", ("multi_file", "pipeline", "cross_skill"), "MEDIUM"),
)


SKILL_POLICY_PROFILES: tuple[SkillPolicyProfile, ...] = (
    SkillPolicyProfile(
        "baseline",
        "No policy override; report-only benchmark.",
        "HIGH",
        True,
        True,
    ),
    SkillPolicyProfile("strict", "CI and third-party skill review.", "MEDIUM", True, True),
    SkillPolicyProfile(
        "permissive",
        "Developer exploration with fewer blocks.",
        "CRITICAL",
        False,
        False,
    ),
    SkillPolicyProfile("compliance-audit", "Evidence-heavy compliance scan.", "MEDIUM", True, True),
    SkillPolicyProfile(
        "internal-tooling",
        "Trusted internal skills with warnings.",
        "HIGH",
        True,
        False,
    ),
    SkillPolicyProfile("max-sensitivity", "High-recall review mode.", "LOW", True, True),
)


def skill_eval_manifest() -> dict[str, Any]:
    return {
        "categories": [asdict(category) for category in SKILL_EVAL_CATEGORIES],
        "policy_profiles": [asdict(profile) for profile in SKILL_POLICY_PROFILES],
        "category_count": len(SKILL_EVAL_CATEGORIES),
        "policy_profile_count": len(SKILL_POLICY_PROFILES),
    }


def discover_skill_eval_fixtures(root: str | Path) -> dict[str, list[str]]:
    base = Path(root)
    fixtures: dict[str, list[str]] = {category.name: [] for category in SKILL_EVAL_CATEGORIES}
    if not base.exists():
        return fixtures
    for skill_file in base.rglob("SKILL.md"):
        rel = str(skill_file.parent.relative_to(base))
        for category in fixtures:
            if f"/{category}/" in f"/{rel}/" or rel.startswith(category):
                fixtures[category].append(rel)
    return {key: sorted(value) for key, value in fixtures.items()}


__all__ = [
    "SKILL_EVAL_CATEGORIES",
    "SKILL_POLICY_PROFILES",
    "SkillEvalCategory",
    "SkillPolicyProfile",
    "discover_skill_eval_fixtures",
    "skill_eval_manifest",
]
