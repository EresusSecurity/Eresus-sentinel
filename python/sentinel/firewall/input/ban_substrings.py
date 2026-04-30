"""
Eresus Sentinel — Ban Substrings Scanner.

Blocks or flags prompts/responses containing configurable
substring or regex patterns.

Use cases:
    - Block competitor mentions
    - Block specific keywords/phrases
    - Block internal codenames
    - Enforce content policies
"""

from __future__ import annotations

import logging
import re
from typing import Optional

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import InputScanner, OutputScanner, ScanAction, ScanResult

logger = logging.getLogger(__name__)


class BanSubstringsScanner(InputScanner):
    """
    Blocks prompts containing specified substrings or patterns.

    Supports:
    - Case-insensitive substring matching
    - Regex pattern matching
    - Word boundary matching
    - Custom severity per pattern
    """

    def __init__(
        self,
        substrings: Optional[list[str]] = None,
        patterns: Optional[list[str]] = None,
        case_sensitive: bool = False,
        match_word: bool = False,
        severity: str = "MEDIUM",
    ):
        """
        Args:
            substrings: List of substrings to ban.
            patterns: List of regex patterns to ban.
            case_sensitive: Whether matching is case-sensitive.
            match_word: Match only whole words.
            severity: Default severity for matches.
        """
        self._case_sensitive = case_sensitive
        flags = 0 if case_sensitive else re.IGNORECASE
        self._severity = Severity[severity.upper()] if hasattr(Severity, severity.upper()) else Severity.MEDIUM

        self._compiled: list[tuple[re.Pattern, str]] = []

        for s in (substrings or []):
            if match_word:
                escaped = re.escape(s)
                p = re.compile(rf"\b{escaped}\b", flags)
            else:
                p = re.compile(re.escape(s), flags)
            self._compiled.append((p, s))

        for pat in (patterns or []):
            try:
                p = re.compile(pat, flags)
                self._compiled.append((p, pat))
            except re.error:
                logger.warning("Invalid ban pattern: %s", pat)

    def scan(self, prompt: str) -> ScanResult:
        if not prompt or not self._compiled:
            return ScanResult(sanitized=prompt, action=ScanAction.PASS, risk_score=0.0)

        findings = []
        for pattern, label in self._compiled:
            match = pattern.search(prompt)
            if match:
                findings.append(Finding.firewall_input(
                    rule_id="FIREWALL-INPUT-070",
                    title=f"Banned content detected: {label[:60]}",
                    description=(
                        f"Input contains banned pattern '{label[:80]}'. "
                        f"Matched: '{match.group(0)[:80]}'"
                    ),
                    severity=self._severity,
                    confidence=1.0,
                    target="<prompt>",
                    evidence=f"Pattern: {label}, Match: {match.group(0)[:120]}",
                    cwe_ids=["CWE-20"],
                    tags=["owasp:llm02", "category:content-policy"],
                    remediation="Remove or rephrase banned content.",
                ))

        if not findings:
            return ScanResult(sanitized=prompt, action=ScanAction.PASS, risk_score=0.0)

        return ScanResult(
            sanitized=prompt,
            action=ScanAction.BLOCK,
            risk_score=0.95,
            findings=findings,
        )


class BanSubstringsOutputScanner(OutputScanner):
    """Blocks responses containing banned substrings."""

    def __init__(self, **kwargs):
        self._scanner = BanSubstringsScanner(**kwargs)

    def scan(self, prompt: str, output: str) -> ScanResult:
        return self._scanner.scan(output)


class BanCompetitorsLegacyScanner(BanSubstringsScanner):
    """
    Blocks prompts attempting to discuss or compare competitors.

    Pre-configured substring scanner with competitor-specific patterns.
    Legacy alias — the canonical implementation is in ban_competitors.py.
    """

    def __init__(self, competitors: list[str] | None = None, **kwargs):
        patterns = []
        for c in (competitors or []):
            patterns.append(rf"\b{re.escape(c)}\b")
        super().__init__(
            patterns=patterns,
            match_word=True,
            severity="LOW",
            **kwargs,
        )
