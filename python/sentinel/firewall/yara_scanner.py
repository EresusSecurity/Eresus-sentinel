"""YARA-based prompt injection scanner.

Compiles YARA rules from rules/yara/ directory and matches against
prompt text for pattern-based injection detection.

Inspired by: vigil-llm YARA scanner approach.
"""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Optional

from ..finding import Finding, Severity, Location

logger = logging.getLogger(__name__)

# Rule file directory (relative to project root)
_DEFAULT_RULES_DIR = Path(__file__).parent.parent.parent.parent / "rules" / "yara"


class YaraPromptScanner:
    """YARA rule-based prompt injection scanner."""

    def __init__(self, rules_dir: Optional[str | Path] = None):
        self._rules_dir = Path(rules_dir) if rules_dir else _DEFAULT_RULES_DIR
        self._compiled = None
        self._available = self._check_yara()

    @staticmethod
    def _check_yara() -> bool:
        try:
            import yara  # noqa: F401
            return True
        except ImportError:
            return False

    def _compile_rules(self):
        """Compile all .yar/.yara files from the rules directory."""
        if not self._available:
            return
        if self._compiled is not None:
            return

        import yara

        filepaths: dict[str, str] = {}
        if self._rules_dir.is_dir():
            for f in sorted(self._rules_dir.iterdir()):
                if f.suffix in (".yar", ".yara"):
                    filepaths[f.stem] = str(f)

        if filepaths:
            try:
                self._compiled = yara.compile(filepaths=filepaths)
                logger.debug("Compiled %d YARA rule files", len(filepaths))
            except yara.Error as exc:
                logger.warning("YARA compilation failed: %s", exc)
                self._compiled = None
        else:
            logger.debug("No YARA rules found in %s", self._rules_dir)

    def scan(self, text: str, source: str = "<prompt>") -> list[Finding]:
        """Scan text against compiled YARA rules."""
        if not self._available:
            return self._fallback_scan(text, source)

        self._compile_rules()
        if self._compiled is None:
            return self._fallback_scan(text, source)

        findings: list[Finding] = []
        try:
            matches = self._compiled.match(data=text.encode("utf-8", errors="replace"))
            for match in matches:
                meta = match.meta or {}
                severity_str = meta.get("severity", "MEDIUM").upper()
                severity = getattr(Severity, severity_str, Severity.MEDIUM)

                findings.append(Finding(
                    rule_id=f"YARA-{match.rule}",
                    title=f"YARA match: {match.rule}",
                    description=meta.get("description", f"YARA rule '{match.rule}' matched"),
                    severity=severity,
                    confidence=float(meta.get("confidence", 0.8)),
                    scanner="yara_prompt",
                    target=source,
                    evidence=f"Rule: {match.rule}, tags: {match.tags}",
                    location=Location(file=source),
                    tags=list(match.tags) + ["yara", "prompt-injection"],
                ))
        except Exception as exc:
            logger.debug("YARA scan error: %s", exc)

        return findings

    def _fallback_scan(self, text: str, source: str) -> list[Finding]:
        """Regex fallback when yara-python is not installed."""
        import re

        findings: list[Finding] = []
        text_lower = text.lower()

        patterns: list[tuple[str, str, str, Severity, float]] = [
            (
                r"(?:ignore|disregard|skip|forget|neglect|overlook)\s+(?:\w+\s+)*?(?:prior|previous|preceding|above|earlier|all)?\s*(?:\w+\s+)*?(?:instructions?|commands?|directives?|context|rules?)",
                "instruction_bypass",
                "Instruction bypass attempt detected",
                Severity.HIGH, 0.85,
            ),
            (
                r"<\|im_start\|>system|<<SYS>>|\[INST\]|###\s*(?:System|Assistant):",
                "system_delimiter",
                "System message delimiter injection detected",
                Severity.HIGH, 0.9,
            ),
            (
                r"\{\{#(?:system|user|assistant)~?\}\}",
                "guidance_injection",
                "Guidance framework template injection detected",
                Severity.HIGH, 0.85,
            ),
            (
                r"(?:Thought|Action|Observation)\s*:\s*\{",
                "react_injection",
                "ReAct agent prompt injection detected",
                Severity.MEDIUM, 0.7,
            ),
            (
                r"!\[(?:[^\]]*)\]\(https?://[^)]*\?(?:[^)]*(?:data|token|key|secret|password))",
                "markdown_exfil",
                "Markdown image data exfiltration attempt detected",
                Severity.HIGH, 0.9,
            ),
            (
                r"(?:AKIA[0-9A-Z]{16}|xox[baprs]-[0-9a-zA-Z-]{10,}|[rs]k_(?:live|test)_[0-9a-zA-Z]{24,})",
                "api_token_leak",
                "API token/key detected in prompt",
                Severity.HIGH, 0.95,
            ),
            (
                r"-----BEGIN\s+(?:RSA|DSA|EC|OPENSSH|PGP)?\s*PRIVATE\s+KEY-----",
                "ssh_key_leak",
                "SSH private key detected in prompt",
                Severity.CRITICAL, 0.99,
            ),
            (
                r"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d\d?)\b",
                "ip_address",
                "IP address detected in prompt (potential SSRF indicator)",
                Severity.LOW, 0.6,
            ),
        ]

        for regex, rule_name, desc, severity, confidence in patterns:
            if re.search(regex, text, re.IGNORECASE):
                findings.append(Finding(
                    rule_id=f"YARA-{rule_name}",
                    module="firewall",
                    title=f"Pattern match: {rule_name}",
                    description=desc,
                    severity=severity,
                    confidence=confidence,
                    target=source,
                    evidence=f"Regex pattern: {rule_name}",
                    location=Location(file=source),
                    tags=["prompt-injection", rule_name],
                ))

        return findings
