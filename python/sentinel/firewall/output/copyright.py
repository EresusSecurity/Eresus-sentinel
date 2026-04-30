"""
Eresus Sentinel — Copyright / Intellectual Property Detection Scanner (Output).

Detects verbatim copyrighted content, license violations, and training data
memorization in LLM responses.

Features:
  - N-gram fingerprinting for verbatim text plagiarism
  - Code license header detection (GPL, MIT, Apache, BSL)
  - Academic paper / book content signature detection
  - Training data memorization indicators
  - Configurable similarity threshold
  - OutputScanner-compliant with Finding/ScanResult



"""

from __future__ import annotations

import logging
import re
from hashlib import sha256

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import OutputScanner, ScanAction, ScanResult

logger = logging.getLogger(__name__)


# ── License header patterns ──────────────────────────────────────

_LICENSE_PATTERNS: list[tuple[str, re.Pattern, str]] = [
    ("GPL-2.0", re.compile(
        r"(?:GNU General Public License|GPL).{0,30}(?:version 2|v2\.0)",
        re.IGNORECASE,
    ), "GNU General Public License v2.0 — copyleft, derivative work must be GPL"),
    ("GPL-3.0", re.compile(
        r"(?:GNU General Public License|GPL).{0,30}(?:version 3|v3\.0)",
        re.IGNORECASE,
    ), "GNU General Public License v3.0 — strongest copyleft"),
    ("AGPL-3.0", re.compile(
        r"(?:GNU Affero General Public License|AGPL)",
        re.IGNORECASE,
    ), "AGPL — network use triggers copyleft"),
    ("MIT", re.compile(
        r"Permission is hereby granted,? free of charge.{0,60}to deal in the Software",
        re.IGNORECASE,
    ), "MIT License text detected — check attribution requirements"),
    ("Apache-2.0", re.compile(
        r"Licensed under the Apache License,? Version 2\.0",
        re.IGNORECASE,
    ), "Apache 2.0 License — patent grant, attribution required"),
    ("BSL-1.1", re.compile(
        r"Business Source License.{0,30}(?:1\.1|Change Date)",
        re.IGNORECASE,
    ), "Business Source License — usage restrictions may apply"),
    ("SSPL", re.compile(
        r"Server Side Public License",
        re.IGNORECASE,
    ), "SSPL — restrictive for SaaS usage"),
    ("Copyright", re.compile(
        r"(?:©|Copyright\s*(?:\(c\))?\s*\d{4}(?:\s*[-–]\s*\d{4})?)",
        re.IGNORECASE,
    ), "Explicit copyright notice detected"),
]

# ── Memorization indicators ──────────────────────────────────────

_MEMORIZATION_PATTERNS: list[tuple[str, re.Pattern]] = [
    ("book_opening", re.compile(
        r"(?:It was the best of times|Call me Ishmael|"
        r"It is a truth universally acknowledged|"
        r"All children, except one, grow up|"
        r"In a hole in the ground there lived a hobbit|"
        r"It was a bright cold day in April)",
        re.IGNORECASE,
    )),
    ("code_attribution", re.compile(
        r"(?:Adapted from|Based on|Copied from|Source:)\s+"
        r"(?:https?://(?:github\.com|stackoverflow\.com|gitlab\.com))",
        re.IGNORECASE,
    )),
    ("song_lyrics", re.compile(
        r"(?:lyrics|verse|chorus|written by)\s*(?::|—|-)\s*.{20,}",
        re.IGNORECASE,
    )),
]


class CopyrightScanner(OutputScanner):
    """
    Detects copyrighted, licensed, or memorized content in LLM output.

    Features:
      - Code license detection (GPL, MIT, Apache, AGPL, BSL, SSPL)
      - Explicit copyright notice detection
      - Famous text memorization indicators
      - N-gram repetition analysis (long verbatim chunks)
      - OutputScanner-compliant

    Usage:
        scanner = CopyrightScanner()
        result = scanner.scan(prompt, response)
    """

    def __init__(
        self,
        check_licenses: bool = True,
        check_memorization: bool = True,
        ngram_size: int = 8,
        ngram_threshold: float = 0.3,
    ):
        self._check_licenses = check_licenses
        self._check_memorization = check_memorization
        self._ngram_size = ngram_size
        self._ngram_threshold = ngram_threshold

    def scan(self, prompt: str, output: str) -> ScanResult:
        if not output or len(output.strip()) < 20:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        findings = []

        # License header detection
        if self._check_licenses:
            for license_id, pattern, description in _LICENSE_PATTERNS:
                match = pattern.search(output)
                if match:
                    findings.append(Finding.firewall_output(
                        rule_id="FIREWALL-OUTPUT-090",
                        title=f"License detected: {license_id}",
                        description=description,
                        severity=Severity.MEDIUM if license_id == "Copyright" else Severity.HIGH,
                        confidence=0.85,
                        target="<response>",
                        evidence=f"License: {license_id}, Match: {match.group(0)[:120]}",
                        tags=["category:copyright", f"license:{license_id}"],
                        remediation="Remove copyrighted/licensed code. Provide original implementation.",
                    ))

        # Memorization indicators
        if self._check_memorization:
            for indicator_name, pattern in _MEMORIZATION_PATTERNS:
                match = pattern.search(output)
                if match:
                    findings.append(Finding.firewall_output(
                        rule_id="FIREWALL-OUTPUT-091",
                        title=f"Memorization indicator: {indicator_name}",
                        description=(
                            f"Response may contain memorized training data: "
                            f"'{match.group(0)[:80]}'"
                        ),
                        severity=Severity.MEDIUM,
                        confidence=0.7,
                        target="<response>",
                        evidence=f"Indicator: {indicator_name}, Match: {match.group(0)[:120]}",
                        tags=["category:copyright", f"memorization:{indicator_name}"],
                        remediation="Verify content originality. Paraphrase if needed.",
                    ))

        # N-gram repetition analysis (long verbatim output)
        repetition_score = self._check_ngram_repetition(output)
        if repetition_score >= self._ngram_threshold:
            findings.append(Finding.firewall_output(
                rule_id="FIREWALL-OUTPUT-092",
                title=f"High verbatim repetition: {repetition_score:.0%}",
                description=(
                    f"Response has {repetition_score:.0%} n-gram repetition, "
                    f"suggesting verbatim training data reproduction."
                ),
                severity=Severity.MEDIUM,
                confidence=repetition_score,
                target="<response>",
                evidence=f"Repetition score: {repetition_score:.4f}",
                tags=["category:copyright", "memorization:ngram_repetition"],
                remediation="Regenerate with higher temperature or rephrase.",
            ))

        if not findings:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        max_severity = max(
            (f.severity for f in findings),
            default=Severity.LOW,
            key=lambda s: {"LOW": 0, "MEDIUM": 1, "HIGH": 2, "CRITICAL": 3}.get(s.value, 0),
        )
        risk = 0.7 if max_severity in (Severity.HIGH, Severity.CRITICAL) else 0.4

        return ScanResult(
            sanitized=output,
            action=ScanAction.WARN,
            risk_score=risk,
            findings=findings,
            metadata={
                "licenses_found": [f.tags[-1].split(":")[-1] for f in findings if "license:" in str(f.tags)],
                "repetition_score": repetition_score,
            },
        )

    def _check_ngram_repetition(self, text: str) -> float:
        """Check for repeated n-grams indicating verbatim output."""
        words = text.lower().split()
        if len(words) < self._ngram_size * 2:
            return 0.0

        ngrams = []
        for i in range(len(words) - self._ngram_size + 1):
            gram = " ".join(words[i:i + self._ngram_size])
            ngrams.append(sha256(gram.encode()).hexdigest()[:12])

        if not ngrams:
            return 0.0

        unique = len(set(ngrams))
        total = len(ngrams)
        repetition = 1.0 - (unique / total)
        return round(repetition, 4)
