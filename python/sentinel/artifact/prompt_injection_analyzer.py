"""
Eresus Sentinel — Deep Prompt Injection Analyzer.

Detects prompt injection and jailbreak patterns in:
  - chat_template fields (Jinja2 SSTI)
  - Model card / README text
  - System prompt fields in config.json
  - Dataset templates and instruction fields

Detection layers:
  1. Hidden Unicode: zero-width / RTL override (codepoints from YAML)
  2. DAN / jailbreak / agent-hijack patterns (from rules/injection_patterns.yaml)
  3. Social engineering patterns (from rules/prompt_injection_ioc_rules.yaml)
  4. IOC patterns: C2 URLs, webhooks, onion, ngrok (from YAML)
  5. Base64-encoded hidden instructions (dangerous decoded content)

All regex patterns are loaded from YAML — zero hardcoded patterns.
"""

from __future__ import annotations

import base64
import json
import logging
import re
import unicodedata
from functools import lru_cache
from pathlib import Path
from typing import Iterator

import yaml

from ..finding import Finding, Severity

logger = logging.getLogger(__name__)

_RULES_DIR = Path(__file__).resolve().parent.parent.parent.parent / "rules"

# ── YAML loaders ─────────────────────────────────────────────────────────────

@lru_cache(maxsize=1)
def _load_injection_patterns() -> list[tuple[re.Pattern, str, str]]:
    """Load DAN/jailbreak/agent-hijack patterns from injection_patterns.yaml.
    Returns list of (compiled_re, severity, description).
    """
    path = _RULES_DIR / "injection_patterns.yaml"
    compiled: list[tuple[re.Pattern, str, str]] = []
    try:
        data = yaml.safe_load(path.read_text(encoding="utf-8"))
    except Exception as e:
        logger.warning("Failed to load injection_patterns.yaml: %s", e)
        return compiled

    # injection_patterns.yaml is a dict of category → list of {pattern, name, severity}
    for category, entries in data.items():
        if not isinstance(entries, list):
            continue
        for entry in entries:
            if not isinstance(entry, dict):
                continue
            raw = entry.get("pattern") or entry.get("regex") or ""
            if not raw:
                continue
            sev_str = str(entry.get("severity", "HIGH")).upper()
            name    = entry.get("name") or entry.get("description") or category
            try:
                compiled.append((re.compile(raw), sev_str, name))
            except re.error as e:
                logger.debug("Skipping bad pattern in injection_patterns.yaml [%s]: %s — %s", category, raw[:60], e)
    return compiled


@lru_cache(maxsize=1)
def _load_ioc_rules() -> dict:
    """Load IOC, social engineering, and hidden unicode codepoints from
    prompt_injection_ioc_rules.yaml.
    """
    path = _RULES_DIR / "prompt_injection_ioc_rules.yaml"
    try:
        return yaml.safe_load(path.read_text(encoding="utf-8")) or {}
    except Exception as e:
        logger.warning("Failed to load prompt_injection_ioc_rules.yaml: %s", e)
        return {}


@lru_cache(maxsize=1)
def _compiled_ioc() -> list[tuple[re.Pattern, str, str]]:
    """Compile IOC patterns from YAML."""
    data = _load_ioc_rules()
    compiled = []
    for entry in data.get("ioc_patterns", []):
        raw = entry.get("pattern", "")
        sev = str(entry.get("severity", "MEDIUM")).upper()
        desc = entry.get("description", raw[:60])
        try:
            compiled.append((re.compile(raw), sev, desc))
        except re.error as e:
            logger.debug("Skipping bad IOC pattern: %s — %s", raw[:60], e)
    return compiled


@lru_cache(maxsize=1)
def _compiled_social_eng() -> list[tuple[re.Pattern, str, str]]:
    """Compile social engineering patterns from YAML."""
    data = _load_ioc_rules()
    compiled = []
    for entry in data.get("social_engineering", []):
        raw = entry.get("pattern", "")
        sev = str(entry.get("severity", "MEDIUM")).upper()
        desc = entry.get("description", raw[:60])
        try:
            compiled.append((re.compile(raw), sev, desc))
        except re.error as e:
            logger.debug("Skipping bad social-eng pattern: %s — %s", raw[:60], e)
    return compiled


@lru_cache(maxsize=1)
def _unicode_sets() -> tuple[frozenset, frozenset]:
    """Return (zero_width_chars, rtl_override_chars) from YAML codepoints."""
    data = _load_ioc_rules()
    uc = data.get("hidden_unicode", {})
    zw  = frozenset(chr(int(cp, 16)) for cp in uc.get("zero_width", []))
    rtl = frozenset(chr(int(cp, 16)) for cp in uc.get("rtl_override", []))
    return zw, rtl


# ── Base64 decoder (no YAML needed — structural pattern) ─────────────────────

_B64_MIN_LEN = 24
_B64_RE = re.compile(r"[A-Za-z0-9+/]{" + str(_B64_MIN_LEN) + r",}={0,2}")
_DANGEROUS_DECODED = re.compile(
    r"(?i)(os\.system|subprocess|eval\(|exec\(|import\s+os|__import__|"
    r"ignore previous|system prompt|tool_call|exfiltrat|backdoor|payload)"
)


class PromptInjectionAnalyzer:
    """
    Deep prompt injection and jailbreak detector.

    All patterns loaded from:
      rules/injection_patterns.yaml           — DAN/jailbreak/agent-hijack (255+ patterns)
      rules/prompt_injection_ioc_rules.yaml   — IOC, social engineering, hidden unicode
    """

    def analyze_text(self, text: str, source: str) -> list[Finding]:
        findings: list[Finding] = []
        findings.extend(self._check_hidden_unicode(text, source))
        findings.extend(self._check_injection_patterns(text, source))
        findings.extend(self._check_social_engineering(text, source))
        findings.extend(self._check_ioc(text, source))
        findings.extend(self._check_b64_hidden(text, source))
        return findings

    def analyze_json_file(self, path: str | Path) -> list[Finding]:
        path = Path(path)
        findings: list[Finding] = []
        try:
            data = json.loads(path.read_text(encoding="utf-8", errors="replace"))
        except Exception:
            return findings
        for value, field_path in _walk_json_strings(data):
            sub = self.analyze_text(value, f"{path}::{field_path}")
            for f in sub:
                f.target = str(path)
            findings.extend(sub)
        return findings

    def analyze_file(self, path: str | Path) -> list[Finding]:
        path = Path(path)
        if path.suffix.lower() == ".json":
            return self.analyze_json_file(path)
        try:
            text = path.read_text(encoding="utf-8", errors="replace")
        except Exception:
            return []
        return self.analyze_text(text, str(path))

    def _check_hidden_unicode(self, text: str, source: str) -> list[Finding]:
        findings = []
        zw_chars, rtl_chars = _unicode_sets()
        found_zw  = [ch for ch in text if ch in zw_chars]
        found_rtl = [ch for ch in text if ch in rtl_chars]

        if found_zw:
            names = list({unicodedata.name(ch, f"U+{ord(ch):04X}") for ch in found_zw})[:5]
            findings.append(Finding.artifact(
                rule_id="PINJ-001",
                title="Hidden zero-width Unicode characters detected",
                description=(
                    "Zero-width or invisible Unicode characters found in text. "
                    "These can hide malicious instructions invisible to humans "
                    "but processed by LLMs (Unicode steganography)."
                ),
                severity=Severity.HIGH,
                confidence=0.9,
                target=source,
                evidence=f"chars={names}, count={len(found_zw)}",
                remediation="Strip zero-width characters before processing with LLM",
            ))

        if found_rtl:
            findings.append(Finding.artifact(
                rule_id="PINJ-002",
                title="RTL override character — text direction manipulation",
                description=(
                    "Right-to-left override or bidirectional control characters found. "
                    "These reverse displayed text to hide malicious content "
                    "(e.g. 'exe.malicious' displayed as 'suoicilam.exe')."
                ),
                severity=Severity.CRITICAL,
                confidence=0.95,
                target=source,
                evidence=f"RTL chars: {[hex(ord(c)) for c in set(found_rtl)]}",
                remediation="Remove all bidirectional override characters",
            ))
        return findings

    def _check_injection_patterns(self, text: str, source: str) -> list[Finding]:
        findings = []
        seen: set[str] = set()
        for compiled_re, sev_str, desc in _load_injection_patterns():
            m = compiled_re.search(text)
            if m and desc not in seen:
                seen.add(desc)
                severity = getattr(Severity, sev_str, Severity.HIGH)
                snippet  = text[max(0, m.start() - 30):m.end() + 50].replace("\n", " ")
                findings.append(Finding.artifact(
                    rule_id="PINJ-010",
                    title=f"Prompt injection pattern: {desc}",
                    description=(
                        f"Detected prompt injection / jailbreak pattern in model content. "
                        f"Pattern: {desc}. May override safety guidelines or hijack agent behavior."
                    ),
                    severity=severity,
                    confidence=0.85,
                    target=source,
                    evidence=f"match={snippet!r:.120}",
                    remediation="Remove injection patterns before deploying model",
                ))
        return findings

    def _check_social_engineering(self, text: str, source: str) -> list[Finding]:
        findings = []
        for compiled_re, sev_str, desc in _compiled_social_eng():
            m = compiled_re.search(text)
            if m:
                severity = getattr(Severity, sev_str, Severity.MEDIUM)
                snippet  = text[max(0, m.start() - 20):m.end() + 60].replace("\n", " ")
                findings.append(Finding.artifact(
                    rule_id="PINJ-020",
                    title=f"Social engineering pattern: {desc}",
                    description=(
                        f"Social engineering instruction detected in model content: {desc}."
                    ),
                    severity=severity,
                    confidence=0.8,
                    target=source,
                    evidence=f"match={snippet!r:.120}",
                    remediation="Remove social engineering content from model documentation",
                ))
        return findings

    def _check_ioc(self, text: str, source: str) -> list[Finding]:
        findings = []
        for compiled_re, sev_str, desc in _compiled_ioc():
            for m in compiled_re.finditer(text):
                severity = getattr(Severity, sev_str, Severity.MEDIUM)
                findings.append(Finding.artifact(
                    rule_id="PINJ-030",
                    title=f"IOC in model content: {desc}",
                    description=(
                        f"Indicator of compromise found: {desc}. "
                        "May indicate C2 infrastructure, exfiltration endpoint, or payload staging."
                    ),
                    severity=severity,
                    confidence=0.85,
                    target=source,
                    evidence=f"ioc={m.group(0)!r:.100}",
                    remediation="Investigate the URL/identifier and block if malicious",
                ))
        return findings

    def _check_b64_hidden(self, text: str, source: str) -> list[Finding]:
        findings = []
        for m in _B64_RE.finditer(text):
            b64str = m.group(0)
            try:
                decoded = base64.b64decode(b64str + "==").decode("utf-8", errors="ignore")
                if _DANGEROUS_DECODED.search(decoded):
                    findings.append(Finding.artifact(
                        rule_id="PINJ-040",
                        title="Base64-encoded hidden instruction with dangerous content",
                        description=(
                            "A base64-encoded string decoded to dangerous content "
                            "(shell commands, eval, import os, or prompt injection keywords). "
                            "May be an obfuscated payload."
                        ),
                        severity=Severity.HIGH,
                        confidence=0.75,
                        target=source,
                        evidence=f"b64={b64str[:40]}... decoded_snippet={decoded[:80]!r}",
                        remediation="Investigate base64 content and remove if malicious",
                    ))
            except Exception:
                pass
        return findings


def _walk_json_strings(obj: object, path: str = "") -> Iterator[tuple[str, str]]:
    """Recursively yield (string_value, json_path) from a parsed JSON object."""
    if isinstance(obj, str):
        yield obj, path
    elif isinstance(obj, dict):
        for k, v in obj.items():
            yield from _walk_json_strings(v, f"{path}.{k}" if path else k)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            yield from _walk_json_strings(item, f"{path}[{i}]")
