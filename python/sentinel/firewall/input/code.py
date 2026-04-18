"""
Eresus Sentinel — Code Detection Scanner.

Detects code snippets in prompts (input) or responses (output).
Useful for preventing:
  - Code injection via prompts
  - LLM outputting executable code when not expected
  - Exfiltration of code through model outputs
"""

from __future__ import annotations

import logging
import re

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import InputScanner, OutputScanner, ScanResult, ScanAction

logger = logging.getLogger(__name__)

CODE_PATTERNS: dict[str, list[re.Pattern]] = {
    "python": [
        re.compile(r"^\s*(?:import|from)\s+\w+", re.MULTILINE),
        re.compile(r"^\s*def\s+\w+\s*\(", re.MULTILINE),
        re.compile(r"^\s*class\s+\w+\s*[:(]", re.MULTILINE),
        re.compile(r"^\s*(?:if|elif|else|for|while|try|except|with)\b.*:", re.MULTILINE),
        re.compile(r"__\w+__"),
    ],
    "javascript": [
        re.compile(r"\b(?:const|let|var)\s+\w+\s*=", re.MULTILINE),
        re.compile(r"\bfunction\s+\w+\s*\(", re.MULTILINE),
        re.compile(r"=>\s*\{", re.MULTILINE),
        re.compile(r"\brequire\s*\(", re.MULTILINE),
        re.compile(r"\bconsole\.\w+\s*\(", re.MULTILINE),
    ],
    "shell": [
        re.compile(r"^\s*#!/\w+", re.MULTILINE),
        re.compile(r"\b(?:sudo|chmod|chown|rm\s+-rf|curl|wget)\b"),
        re.compile(r"\beval\s+\$", re.MULTILINE),
        re.compile(r";\s*(?:cat|echo|base64|nc|ncat)\s+"),
    ],
    "sql": [
        re.compile(r"\b(?:SELECT|INSERT|UPDATE|DELETE|DROP|ALTER|CREATE)\s+", re.IGNORECASE),
        re.compile(r"\bUNION\s+(?:ALL\s+)?SELECT\b", re.IGNORECASE),
        re.compile(r";\s*--", re.MULTILINE),
    ],
    "html_xml": [
        re.compile(r"<script[\s>]", re.IGNORECASE),
        re.compile(r"<iframe[\s>]", re.IGNORECASE),
        re.compile(r"on(?:load|error|click|mouseover)\s*=", re.IGNORECASE),
        re.compile(r"javascript\s*:", re.IGNORECASE),
    ],
    "csharp_java": [
        re.compile(r"\bpublic\s+(?:static|class|void|int|string)\b"),
        re.compile(r"\bSystem\.\w+\.\w+\s*\("),
        re.compile(r"\bnew\s+\w+\s*\(.*\)\s*;"),
    ],
}

FENCED_CODE = re.compile(r"```\w*\n[\s\S]*?```")


class CodeScanner(InputScanner):
    """
    Detects code in input prompts.

    Flags prompts containing executable code patterns from
    multiple languages (Python, JS, Shell, SQL, HTML, C#/Java).
    """

    def __init__(
        self,
        languages: list[str] | None = None,
        block: bool = False,
        threshold: int = 2,
    ):
        """
        Args:
            languages: Languages to detect. None = all.
            block: Whether to block (True) or warn (False).
            threshold: Minimum pattern matches to trigger detection.
        """
        self._languages = languages or list(CODE_PATTERNS.keys())
        self._block = block
        self._threshold = threshold

    def scan(self, prompt: str) -> ScanResult:
        if not prompt or len(prompt.strip()) < 10:
            return ScanResult(sanitized=prompt, action=ScanAction.PASS, risk_score=0.0)

        detected: dict[str, int] = {}

        for lang in self._languages:
            patterns = CODE_PATTERNS.get(lang, [])
            count = sum(1 for p in patterns if p.search(prompt))
            if count > 0:
                detected[lang] = count

        fenced = len(FENCED_CODE.findall(prompt))
        total_matches = sum(detected.values()) + fenced

        if total_matches < self._threshold:
            return ScanResult(sanitized=prompt, action=ScanAction.PASS, risk_score=0.0)

        score = min(1.0, total_matches / 10)
        langs = ", ".join(f"{k}({v})" for k, v in detected.items())
        finding = Finding.firewall_input(
            rule_id="FIREWALL-INPUT-100",
            title=f"Code detected in input: {langs}",
            description=(
                f"Input contains code patterns from: {langs}. "
                f"Total matches: {total_matches}, fenced blocks: {fenced}."
            ),
            severity=Severity.MEDIUM if not self._block else Severity.HIGH,
            confidence=score,
            target="<prompt>",
            evidence=f"Languages: {langs}, Fenced: {fenced}, Total: {total_matches}",
            cwe_ids=["CWE-94"],
            tags=["owasp:llm01", "category:code-detection"],
            remediation="Remove code from input or use a code-enabled endpoint.",
        )
        return ScanResult(
            sanitized=prompt,
            action=ScanAction.BLOCK if self._block else ScanAction.WARN,
            risk_score=score,
            findings=[finding],
        )


class BanCodeScanner(CodeScanner):
    """Hard-blocks any code in input prompts."""

    def __init__(self, **kwargs):
        super().__init__(block=True, threshold=1, **kwargs)


class CodeOutputScanner(OutputScanner):
    """Detects code in LLM responses."""

    def __init__(self, **kwargs):
        self._scanner = CodeScanner(**kwargs)

    def scan(self, prompt: str, output: str) -> ScanResult:
        return self._scanner.scan(output)
