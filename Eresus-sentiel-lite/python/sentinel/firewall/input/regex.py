"""
Eresus Sentinel — Regex Pattern Scanner.

Configurable regex-based content scanning for:
  - Custom content policies
  - Domain-specific pattern detection
  - Data format enforcement
  - Custom PII/PHI patterns

Works for both input and output scanning.
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import InputScanner, OutputScanner, ScanResult, ScanAction

logger = logging.getLogger(__name__)


class RegexScanner(InputScanner):
    """
    Scans input against configurable regex patterns.

    Supports named patterns with individual severity levels
    and remediation guidance.
    """

    def __init__(
        self,
        patterns: Optional[dict[str, str]] = None,
        severity: str = "MEDIUM",
        block_on_match: bool = True,
    ):
        """
        Args:
            patterns: Dict of {name: regex_pattern} to scan for.
            severity: Default severity for matches.
            block_on_match: Block (True) or warn (False) on match.
        """
        self._block = block_on_match
        self._severity = Severity[severity.upper()] if hasattr(Severity, severity.upper()) else Severity.MEDIUM
        self._compiled: list[tuple[str, re.Pattern]] = []

        for name, pattern in (patterns or {}).items():
            try:
                self._compiled.append((name, re.compile(pattern, re.IGNORECASE)))
            except re.error as e:
                logger.warning("Invalid regex pattern '%s': %s", name, e)

    def scan(self, prompt: str) -> ScanResult:
        if not prompt or not self._compiled:
            return ScanResult(sanitized=prompt, action=ScanAction.PASS, risk_score=0.0)

        findings = []
        for name, pattern in self._compiled:
            match = pattern.search(prompt)
            if match:
                findings.append(Finding.firewall_input(
                    rule_id="FIREWALL-INPUT-110",
                    title=f"Regex match: {name}",
                    description=(
                        f"Input matched custom regex pattern '{name}': "
                        f"'{match.group(0)[:100]}'"
                    ),
                    severity=self._severity,
                    confidence=1.0,
                    target="<prompt>",
                    evidence=f"Pattern: {name}, Match: {match.group(0)[:150]}",
                    cwe_ids=["CWE-20"],
                    tags=["owasp:llm02", "category:regex"],
                    remediation=f"Input violates content policy: {name}",
                ))

        if not findings:
            return ScanResult(sanitized=prompt, action=ScanAction.PASS, risk_score=0.0)

        return ScanResult(
            sanitized=prompt,
            action=ScanAction.BLOCK if self._block else ScanAction.WARN,
            risk_score=0.9,
            findings=findings,
        )


class RegexOutputScanner(OutputScanner):
    """Scans output against configurable regex patterns."""

    def __init__(self, **kwargs):
        self._scanner = RegexScanner(**kwargs)

    def scan(self, prompt: str, output: str) -> ScanResult:
        return self._scanner.scan(output)
