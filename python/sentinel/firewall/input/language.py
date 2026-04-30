"""
Eresus Sentinel — Language Detection Scanner.

Detects and enforces allowed languages in prompts to prevent
language-based bypass attacks and ensure compliance.

Also provides LanguageSame output scanner to verify response
language matches prompt language.
"""

from __future__ import annotations

import logging
import unicodedata
from typing import Optional

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import InputScanner, OutputScanner, ScanAction, ScanResult

logger = logging.getLogger(__name__)

SCRIPT_RANGES = {
    "latin": (0x0000, 0x02FF),
    "cyrillic": (0x0400, 0x04FF),
    "arabic": (0x0600, 0x06FF),
    "devanagari": (0x0900, 0x097F),
    "chinese": (0x4E00, 0x9FFF),
    "japanese_hiragana": (0x3040, 0x309F),
    "japanese_katakana": (0x30A0, 0x30FF),
    "korean": (0xAC00, 0xD7AF),
    "thai": (0x0E00, 0x0E7F),
    "hebrew": (0x0590, 0x05FF),
    "greek": (0x0370, 0x03FF),
    "turkish": (0x011E, 0x011F),  # Ğğ
}


def detect_scripts(text: str) -> dict[str, int]:
    """Detect Unicode script distribution in text."""
    script_counts: dict[str, int] = {}
    for ch in text:
        if ch.isspace() or ch in '.,;:!?-_()[]{}"\'/\\@#$%^&*+=<>~`':
            continue
        cp = ord(ch)
        for script, (lo, hi) in SCRIPT_RANGES.items():
            if lo <= cp <= hi:
                script_counts[script] = script_counts.get(script, 0) + 1
                break
        else:
            cat = unicodedata.category(ch)
            if cat.startswith("L"):
                script_counts["other"] = script_counts.get("other", 0) + 1
    return script_counts


def detect_primary_language(text: str) -> str:
    """Detect the primary script/language of text."""
    scripts = detect_scripts(text)
    if not scripts:
        return "unknown"
    return max(scripts, key=scripts.get)


class LanguageScanner(InputScanner):
    """
    Enforces allowed languages/scripts in input prompts.

    Detects the dominant Unicode script and blocks if it doesn't
    match the allowed list. Useful for preventing:
    - Language-based injection bypass
    - Script mixing attacks
    - Unintended multilingual content
    """

    def __init__(
        self,
        allowed_scripts: Optional[list[str]] = None,
        block_mixed: bool = False,
        mix_threshold: float = 0.3,
    ):
        """
        Args:
            allowed_scripts: List of allowed script names (e.g., ["latin", "arabic"]).
                None or empty = allow all (detection only).
            block_mixed: Block prompts with significant script mixing.
            mix_threshold: Threshold ratio for secondary script to trigger mixed alert.
        """
        self._allowed = set(s.lower() for s in (allowed_scripts or []))
        self._block_mixed = block_mixed
        self._mix_threshold = mix_threshold

    def scan(self, prompt: str) -> ScanResult:
        if not prompt or len(prompt.strip()) < 5:
            return ScanResult(sanitized=prompt, action=ScanAction.PASS, risk_score=0.0)

        scripts = detect_scripts(prompt)
        if not scripts:
            return ScanResult(sanitized=prompt, action=ScanAction.PASS, risk_score=0.0)

        findings = []
        total = sum(scripts.values())
        primary = max(scripts, key=scripts.get)
        primary_ratio = scripts[primary] / total if total > 0 else 0

        # Enforce allowed scripts
        if self._allowed:
            disallowed = set(scripts.keys()) - self._allowed - {"other"}
            if disallowed:
                findings.append(Finding.firewall_input(
                    rule_id="FIREWALL-INPUT-060",
                    title=f"Disallowed script detected: {', '.join(disallowed)}",
                    description=(
                        f"Input contains {', '.join(disallowed)} script(s) "
                        f"which are not in the allowed list: {', '.join(self._allowed)}"
                    ),
                    severity=Severity.MEDIUM,
                    confidence=0.85,
                    target="<prompt>",
                    evidence=f"Scripts: {scripts}",
                    cwe_ids=["CWE-20"],
                    tags=["owasp:llm01", "category:language"],
                    remediation=f"Restrict input to: {', '.join(self._allowed)}",
                ))

        # Detect abnormal script mixing (potential injection)
        if self._block_mixed and len(scripts) > 1:
            for script, count in scripts.items():
                if script != primary and script != "other":
                    ratio = count / total
                    if ratio > self._mix_threshold:
                        findings.append(Finding.firewall_input(
                            rule_id="FIREWALL-INPUT-061",
                            title="Suspicious script mixing detected",
                            description=(
                                f"Input mixes {primary} ({primary_ratio:.0%}) with "
                                f"{script} ({ratio:.0%}). Script mixing is a common "
                                f"injection bypass technique."
                            ),
                            severity=Severity.MEDIUM,
                            confidence=0.7,
                            target="<prompt>",
                            evidence=f"Scripts: {scripts}, Primary: {primary}",
                            cwe_ids=["CWE-20"],
                            tags=["owasp:llm01", "category:script-mixing"],
                            remediation="Review for potential injection bypass.",
                        ))

        if not findings:
            return ScanResult(sanitized=prompt, action=ScanAction.PASS, risk_score=0.0)

        action = ScanAction.BLOCK if any(f.severity == Severity.HIGH for f in findings) else ScanAction.WARN
        score = max(0.6, primary_ratio if self._allowed and findings else 0.5)
        return ScanResult(sanitized=prompt, action=action, risk_score=score, findings=findings)


class LanguageSameScanner(OutputScanner):
    """
    Verifies that LLM response language matches prompt language.

    Catches language switching attacks where the model is tricked
    into responding in a different language to bypass output scanners.
    """

    def scan(self, prompt: str, output: str) -> ScanResult:
        if not prompt or not output or len(output.strip()) < 10:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        prompt_lang = detect_primary_language(prompt)
        output_lang = detect_primary_language(output)

        if prompt_lang == "unknown" or output_lang == "unknown":
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        if prompt_lang != output_lang:
            finding = Finding.firewall_output(
                rule_id="FIREWALL-OUTPUT-050",
                title="Response language mismatch",
                description=(
                    f"Prompt language ({prompt_lang}) differs from response "
                    f"language ({output_lang}). This may indicate a language "
                    f"switching attack to bypass output scanners."
                ),
                severity=Severity.MEDIUM,
                confidence=0.7,
                target="<response>",
                evidence=f"Prompt: {prompt_lang}, Response: {output_lang}",
                cwe_ids=["CWE-20"],
                tags=["owasp:llm02", "category:language-mismatch"],
                remediation="Ensure response matches the expected language.",
            )
            return ScanResult(
                sanitized=output,
                action=ScanAction.WARN,
                risk_score=0.5,
                findings=[finding],
            )

        return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)
