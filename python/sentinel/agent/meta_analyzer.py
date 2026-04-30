"""Meta-analyzer: second-pass false-positive reduction for skill/agent findings."""
from __future__ import annotations

import logging
from dataclasses import dataclass

from sentinel.finding import Finding, Severity

logger = logging.getLogger(__name__)


@dataclass
class FPRule:
    id: str
    description: str
    rule_ids: list[str]  # findings that match
    condition: str  # "low_confidence", "test_file", "example_code", "documentation"
    action: str = "suppress"  # "suppress", "downgrade", "annotate"


_BUILTIN_FP_RULES: list[FPRule] = [
    FPRule("FP-001", "Suppress low-confidence findings in test files",
           ["*"], "test_file", "suppress"),
    FPRule("FP-002", "Downgrade findings in example/sample directories",
           ["*"], "example_code", "downgrade"),
    FPRule("FP-003", "Suppress very low confidence findings",
           ["*"], "low_confidence", "suppress"),
    FPRule("FP-004", "Annotate documentation-only findings",
           ["*"], "documentation", "annotate"),
]


class MetaAnalyzer:
    """Second-pass analyzer to reduce false positives."""

    def __init__(self, rules: list[FPRule] | None = None) -> None:
        self._rules = rules or list(_BUILTIN_FP_RULES)

    def analyze(self, findings: list[Finding]) -> tuple[list[Finding], list[Finding]]:
        """Returns (kept, suppressed) findings."""
        kept: list[Finding] = []
        suppressed: list[Finding] = []

        for f in findings:
            action = self._evaluate(f)
            if action == "suppress":
                suppressed.append(f)
            elif action == "downgrade":
                f.severity = Severity.LOW
                kept.append(f)
            else:
                kept.append(f)

        if suppressed:
            logger.info("Meta-analyzer suppressed %d/%d findings", len(suppressed), len(findings))
        return kept, suppressed

    def _evaluate(self, finding: Finding) -> str:
        for rule in self._rules:
            if not self._matches_rule_ids(finding, rule.rule_ids):
                continue
            if self._matches_condition(finding, rule.condition):
                return rule.action
        return "keep"

    @staticmethod
    def _matches_rule_ids(finding: Finding, rule_ids: list[str]) -> bool:
        if "*" in rule_ids:
            return True
        return finding.rule_id in rule_ids

    @staticmethod
    def _matches_condition(finding: Finding, condition: str) -> bool:
        target = finding.target.lower() if finding.target else ""
        if condition == "test_file":
            return "/test" in target or "test_" in target
        if condition == "example_code":
            return any(d in target for d in ("/example", "/sample", "/demo"))
        if condition == "low_confidence":
            return finding.confidence < 0.3
        if condition == "documentation":
            return target.endswith((".md", ".rst", ".txt"))
        return False

    @property
    def rule_count(self) -> int:
        return len(self._rules)
