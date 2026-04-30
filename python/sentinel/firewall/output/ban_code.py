"""
Output-side code banning scanner — detects and blocks code in model responses.

Production-grade features:
  - 18 language detection patterns loaded from YAML
  - Fenced code block extraction
  - Inline code detection
  - Severity scoring by language risk
  - Auto-redaction option
  - Whitelist patterns (safe code like config examples)
  - OutputScanner-compliant with Finding/ScanResult

Pattern data externalized to: data/ban_code.yaml
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass

from sentinel.data_loader import compile_pattern_list, load_data
from sentinel.finding import Finding, Severity
from sentinel.firewall.base import OutputScanner, ScanAction, ScanResult

logger = logging.getLogger(__name__)

# Fenced code block pattern
FENCED_BLOCK = re.compile(r"```(?:\w+)?\n(.*?)```", re.DOTALL)


# ── YAML-driven data loading ────────────────────────────────────────

_CODE_PATTERNS: dict[str, list[tuple[re.Pattern, float]]] | None = None
_SAFE_PATTERNS: list[re.Pattern] | None = None


def _load_code_patterns() -> tuple[dict[str, list[tuple[re.Pattern, float]]], list[re.Pattern]]:
    data = load_data("ban_code.yaml")

    # Language patterns
    raw_langs = data.get("languages", {})
    code_patterns: dict[str, list[tuple[re.Pattern, float]]] = {}
    for lang, entries in raw_langs.items():
        compiled = []
        for entry in entries:
            regex_str = entry.get("regex", "")
            risk = entry.get("risk", 0.5)
            try:
                pattern = re.compile(regex_str)
                compiled.append((pattern, risk))
            except re.error as e:
                logger.warning("Bad code regex [%s]: %s", lang, e)
        code_patterns[lang] = compiled

    # Safe patterns
    raw_safe = data.get("safe_patterns", [])
    safe = compile_pattern_list(raw_safe, re.IGNORECASE)

    return code_patterns, safe


def _get_patterns() -> dict[str, list[tuple[re.Pattern, float]]]:
    global _CODE_PATTERNS, _SAFE_PATTERNS
    if _CODE_PATTERNS is None:
        _CODE_PATTERNS, _SAFE_PATTERNS = _load_code_patterns()
    return _CODE_PATTERNS


def _get_safe_patterns() -> list[re.Pattern]:
    global _SAFE_PATTERNS
    if _SAFE_PATTERNS is None:
        _get_patterns()  # triggers load
    return _SAFE_PATTERNS or []


# ── Data classes ─────────────────────────────────────────────────────

@dataclass
class CodeDetection:
    """Single code detection result."""
    language: str
    pattern_matched: str
    risk_score: float
    line_content: str
    in_fenced_block: bool


# ── Scanner ──────────────────────────────────────────────────────────

class BanCodeOutputScanner(OutputScanner):
    """
    Blocks model responses containing dangerous code.

    All patterns loaded from data/ban_code.yaml.

    Features:
      - 18 language patterns with risk-weighted scoring
      - Fenced code block detection
      - Safe-pattern whitelist (JSON, YAML configs)
      - Auto-redaction of dangerous blocks
      - Per-language risk scoring
      - OutputScanner-compliant with ScanResult/Finding

    Usage:
        scanner = BanCodeOutputScanner(languages=["python", "shell", "sql"])
        result = scanner.scan("", response_text)
    """

    def __init__(
        self,
        languages: list[str] | None = None,
        threshold: float = 0.6,
        redact: bool = False,
        allow_fenced_safe: bool = True,
    ):
        patterns = _get_patterns()
        self._languages = languages or list(patterns.keys())
        self._threshold = threshold
        self._redact = redact
        self._allow_fenced_safe = allow_fenced_safe

    def scan(self, prompt: str, output: str) -> ScanResult:
        if not output or len(output.strip()) < 10:
            return ScanResult(sanitized=output, action=ScanAction.PASS, risk_score=0.0)

        patterns = _get_patterns()
        safe_patterns = _get_safe_patterns()
        detections: list[CodeDetection] = []
        fenced_blocks = len(FENCED_BLOCK.findall(output))

        # Check if content is in a safe fenced block
        is_safe_block = False
        if self._allow_fenced_safe:
            for safe in safe_patterns:
                if safe.search(output):
                    is_safe_block = True
                    break

        # Scan each language
        for lang in self._languages:
            lang_patterns = patterns.get(lang, [])
            for pattern, risk in lang_patterns:
                for match in pattern.finditer(output):
                    if is_safe_block and risk < 0.9:
                        continue
                    line = match.group(0)[:120]
                    in_fenced = self._is_in_fenced_block(output, match.start())
                    detections.append(CodeDetection(
                        language=lang,
                        pattern_matched=pattern.pattern[:80],
                        risk_score=risk,
                        line_content=line,
                        in_fenced_block=in_fenced,
                    ))

        max_risk = max((d.risk_score for d in detections), default=0.0)
        languages_found = list(set(d.language for d in detections))
        has_code = max_risk >= self._threshold and len(detections) > 0

        if not has_code:
            return ScanResult(
                sanitized=output, action=ScanAction.PASS, risk_score=0.0,
                metadata={"fenced_blocks": fenced_blocks},
            )

        # Redaction
        sanitized = output
        if self._redact:
            sanitized = FENCED_BLOCK.sub("[CODE BLOCK REDACTED]", sanitized)
            for det in detections:
                if det.risk_score >= 0.9:
                    sanitized = sanitized.replace(det.line_content, "[REDACTED]")

        # Severity
        severity = Severity.HIGH if max_risk >= 0.9 else Severity.MEDIUM

        findings = []
        seen_langs = set()
        for det in sorted(detections, key=lambda d: d.risk_score, reverse=True):
            if det.language in seen_langs:
                continue
            seen_langs.add(det.language)
            findings.append(Finding.firewall_output(
                rule_id="FIREWALL-OUTPUT-020",
                title=f"Code detected: {det.language} (risk: {det.risk_score:.2f})",
                description=(
                    f"Response contains {det.language} code "
                    f"with risk score {det.risk_score:.2f}. "
                    f"In fenced block: {det.in_fenced_block}."
                ),
                severity=severity,
                confidence=det.risk_score,
                target="<response>",
                evidence=f"Language: {det.language}, Code: {det.line_content[:100]}",
                cwe_ids=["CWE-94"],
                tags=["owasp:llm02", "category:code_generation", f"language:{det.language}"],
                remediation="Remove executable code from response.",
            ))

        action = ScanAction.BLOCK if max_risk >= 0.95 else ScanAction.WARN

        return ScanResult(
            sanitized=sanitized,
            action=action,
            risk_score=round(max_risk, 4),
            findings=findings,
            metadata={
                "languages_found": languages_found,
                "detection_count": len(detections),
                "fenced_blocks": fenced_blocks,
                "max_risk": round(max_risk, 4),
            },
        )

    @staticmethod
    def _is_in_fenced_block(text: str, pos: int) -> bool:
        before = text[:pos]
        opens = before.count("```")
        return opens % 2 == 1
