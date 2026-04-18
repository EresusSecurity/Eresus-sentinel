"""
SAST Rule Loader & Rule Writer.

Loads SAST rules from YAML, allows dynamic rule registration,
and supports rule severity filtering and whitelisting.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from sentinel.finding import Finding, Severity

logger = logging.getLogger(__name__)


class SASTRuleSet:
    """
    A collection of SAST rules that can be filtered, combined, and serialized.

    Usage:
        rules = SASTRuleSet.from_yaml("rules/sast_rules.yaml")
        rules = rules.filter_severity(min_severity=Severity.MEDIUM)
        findings = rules.scan_file("path/to/file.py")
    """

    def __init__(self, rules: list[dict] | None = None):
        self._rules = rules or []

    @classmethod
    def from_yaml(cls, path: str) -> "SASTRuleSet":
        """Load rules from a YAML file."""
        try:
            import yaml
        except ImportError:
            logger.error("PyYAML is required for SAST rule loading")
            return cls()

        p = Path(path)
        if not p.exists():
            logger.warning("Rule file not found: %s", path)
            return cls()

        import re
        with open(p, "r", encoding="utf-8") as f:
            data = yaml.safe_load(f)

        rules = []
        for category in data.get("rules", []):
            for rule_def in category.get("checks", []):
                try:
                    rules.append({
                        "id": rule_def["id"],
                        "name": rule_def["name"],
                        "description": rule_def.get("description", ""),
                        "severity": rule_def.get("severity", "MEDIUM"),
                        "pattern": re.compile(rule_def["pattern"]),
                        "cwe_ids": rule_def.get("cwe_ids", []),
                        "fix_hint": rule_def.get("fix_hint", ""),
                        "references": rule_def.get("references", []),
                        "languages": rule_def.get("languages", ["python"]),
                    })
                except Exception as exc:
                    logger.warning("Skipping invalid rule %s: %s", rule_def.get("id"), exc)

        return cls(rules)

    def filter_severity(self, min_severity: Severity = Severity.MEDIUM) -> "SASTRuleSet":
        """Return a new ruleset with only rules >= min_severity."""
        severity_order = {
            "CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1, "INFO": 0,
        }
        min_val = severity_order.get(min_severity.name, 0)
        filtered = [
            r for r in self._rules
            if severity_order.get(r["severity"], 0) >= min_val
        ]
        return SASTRuleSet(filtered)

    def filter_language(self, language: str) -> "SASTRuleSet":
        """Return rules applicable to a specific language."""
        filtered = [
            r for r in self._rules
            if language in r.get("languages", ["python"])
        ]
        return SASTRuleSet(filtered)

    @property
    def count(self) -> int:
        return len(self._rules)

    @property
    def rules(self) -> list[dict]:
        return self._rules

    def __len__(self) -> int:
        return len(self._rules)

    def __iter__(self):
        return iter(self._rules)
