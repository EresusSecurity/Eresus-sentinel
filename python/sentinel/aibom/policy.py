"""BOM policy system — enforce rules on AIBOM results."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from enum import Enum
from typing import Any

from sentinel.aibom.models import AIBOMResult, AIComponent

logger = logging.getLogger(__name__)


class PolicyAction(str, Enum):
    ALLOW = "allow"
    WARN = "warn"
    DENY = "deny"
    REQUIRE_REVIEW = "require-review"


@dataclass
class PolicyRule:
    id: str
    description: str
    action: PolicyAction
    condition: str  # component type or property match
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class PolicyViolation:
    rule: PolicyRule
    component: AIComponent
    message: str


class BOMPolicy:
    """Evaluate AIBOM results against a set of policy rules."""

    def __init__(self) -> None:
        self._rules: list[PolicyRule] = []

    def add_rule(self, rule: PolicyRule) -> None:
        self._rules.append(rule)

    def load_defaults(self) -> None:
        self._rules.extend([
            PolicyRule("BOM-001", "Unpinned AI dependency", PolicyAction.WARN,
                       "property:pinned=False"),
            PolicyRule("BOM-002", "No license on model component", PolicyAction.WARN,
                       "license:empty"),
            PolicyRule("BOM-003", "Secret detected in BOM", PolicyAction.DENY,
                       "type:secret"),
            PolicyRule("BOM-004", "Unresolved env var reference", PolicyAction.WARN,
                       "property:resolved=False"),
            PolicyRule("BOM-005", "Shadow AI usage detected", PolicyAction.REQUIRE_REVIEW,
                       "type:shadow_ai"),
        ])

    def evaluate(self, result: AIBOMResult) -> list[PolicyViolation]:
        violations: list[PolicyViolation] = []
        for comp in result.components:
            for rule in self._rules:
                if self._matches(rule, comp):
                    violations.append(PolicyViolation(
                        rule=rule,
                        component=comp,
                        message=f"{rule.description}: {comp.name} ({comp.type.value})",
                    ))
        return violations

    @staticmethod
    def _matches(rule: PolicyRule, comp: AIComponent) -> bool:
        cond = rule.condition
        if cond.startswith("type:"):
            target = cond.split(":", 1)[1]
            return target in comp.type.value
        if cond.startswith("property:"):
            kv = cond.split(":", 1)[1]
            if "=" in kv:
                k, v = kv.split("=", 1)
                actual = comp.properties.get(k)
                if v == "False":
                    return actual is False
                if v == "True":
                    return actual is True
                return str(actual) == v
            return kv in comp.properties
        if cond.startswith("license:"):
            target = cond.split(":", 1)[1]
            if target == "empty":
                return not comp.license
        return False

    @property
    def rule_count(self) -> int:
        return len(self._rules)
