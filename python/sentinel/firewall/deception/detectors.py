"""
Deception guardrail threat detectors.

Each detector class scores a query for a specific threat category.
Patterns are loaded from ``rules/deception_patterns.yaml`` via
:func:`sentinel.rules.load_rules` so that detection logic never
contains hard-coded regex — consistent with the rest of Sentinel.

Fallback: if rules file is unavailable, built-in minimal patterns
are used so the engine can still function in degraded mode.
"""

from __future__ import annotations

import logging
import os
import re
import unicodedata
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from typing import Optional

from sentinel.rules import get_rules_dir, load_yaml

_log = logging.getLogger("sentinel.deception.detectors")


# ---------------------------------------------------------------------------
# Enums
# ---------------------------------------------------------------------------

class ThreatCategory(str, Enum):
    NONE = "none"
    CREDENTIAL_HARVEST = "credential_harvest"
    MALWARE_GENERATION = "malware_generation"
    SOCIAL_ENGINEERING = "social_engineering"
    DATA_EXFILTRATION = "data_exfiltration"
    SYSTEM_RECON = "system_recon"
    JAILBREAK = "jailbreak"
    PROMPT_INJECTION = "prompt_injection"
    HARMFUL_CONTENT = "harmful_content"
    CUSTOM = "custom"


# ---------------------------------------------------------------------------
# Detection result
# ---------------------------------------------------------------------------

@dataclass
class Detection:
    score: float
    category: ThreatCategory
    reason: str
    matched: str = ""
    custom_category_name: str = ""
    template_override: Optional[str] = None


# ---------------------------------------------------------------------------
# Thresholds (tunable via env)
# ---------------------------------------------------------------------------

def _clamp(value: int, lo: int, hi: int, name: str) -> int:
    if value < lo or value > hi:
        _log.warning("Threshold %s=%d out of range [%d, %d] — clamping.", name, value, lo, hi)
    return max(lo, min(hi, value))


SCORE_BLOCK = _clamp(int(os.environ.get("DECEPTION_SCORE_BLOCK", "90")), 50, 100, "DECEPTION_SCORE_BLOCK")
SCORE_DECEIVE = _clamp(int(os.environ.get("DECEPTION_SCORE_DECEIVE", "40")), 1, SCORE_BLOCK - 1, "DECEPTION_SCORE_DECEIVE")
SCORE_WARN = _clamp(int(os.environ.get("DECEPTION_SCORE_WARN", "20")), 1, SCORE_DECEIVE - 1, "DECEPTION_SCORE_WARN")
SESSION_DECEIVE_THRESHOLD = _clamp(
    int(os.environ.get("DECEPTION_SESSION_THRESHOLD", "300")), 50, 100_000, "DECEPTION_SESSION_THRESHOLD"
)

MAX_DETECTION_CHARS = 4096


# ---------------------------------------------------------------------------
# Normalization helper
# ---------------------------------------------------------------------------

def _normalize(text: str) -> str:
    return unicodedata.normalize("NFKC", text).lower()


# ---------------------------------------------------------------------------
# YAML rule loader
# ---------------------------------------------------------------------------

_RULES_DIR = get_rules_dir()


@lru_cache(maxsize=1)
def _load_deception_rules() -> dict:
    """Load deception patterns from YAML. Returns dict of category -> list of (pattern, score)."""
    rules_path = _RULES_DIR / "deception_patterns.yaml"
    try:
        data = load_yaml("deception_patterns.yaml")
    except FileNotFoundError:
        _log.warning("deception_patterns.yaml not found at %s — using empty ruleset", rules_path)
        return {}
    compiled: dict[str, list[tuple[re.Pattern, int]]] = {}
    for category, rules in data.get("categories", {}).items():
        patterns = []
        for rule in rules.get("patterns", []):
            try:
                pat = re.compile(rule["regex"], re.IGNORECASE)
                patterns.append((pat, int(rule.get("score", 50))))
            except re.error as exc:
                _log.error("Invalid regex in deception_patterns.yaml [%s]: %s — %s", category, rule.get("regex", ""), exc)
        compiled[category] = patterns
    return compiled


# ---------------------------------------------------------------------------
# Base detector
# ---------------------------------------------------------------------------

class BaseDetector(ABC):
    """Base class for all deception threat detectors."""

    @abstractmethod
    def score(self, text: str) -> Detection:
        ...


# ---------------------------------------------------------------------------
# Individual detectors
# ---------------------------------------------------------------------------

class HarmfulContentDetector(BaseDetector):
    """Hard-block detector — content where deception is never appropriate (WMD, CSAM)."""

    def __init__(self) -> None:
        rules = _load_deception_rules()
        self._patterns = rules.get("harmful_content", [])
        if not self._patterns:
            self._patterns = [
                (re.compile(r"\b(csam|child.{0,10}(porn|sexual|nude|exploit))\b", re.I), 100),
                (re.compile(r"\b(bioweapon|chemical.?weapon|nerve.?agent|sarin|vx.?gas).{0,30}(synthesize|make|create)\b", re.I), 95),
                (re.compile(r"\b(nuclear|radiolog).{0,20}(weapon|bomb|device).{0,30}(build|construct|make|assemble)\b", re.I), 95),
            ]

    def score(self, text: str) -> Detection:
        norm = _normalize(text)
        best = Detection(0.0, ThreatCategory.HARMFUL_CONTENT, "No match")
        for pat, sc in self._patterns:
            m = pat.search(norm)
            if m and sc > best.score:
                best = Detection(sc, ThreatCategory.HARMFUL_CONTENT, "Blocked: harmful content", m.group())
        return best


class JailbreakDetector(BaseDetector):
    """Detects jailbreak / safety-bypass attempts with 80+ patterns."""

    def __init__(self) -> None:
        rules = _load_deception_rules()
        self._patterns = rules.get("jailbreak", [])
        if not self._patterns:
            # Minimal fallback patterns
            self._patterns = [
                (re.compile(r"\bignore (all )?previous instructions?\b", re.I), 85),
                (re.compile(r"\bdo anything now\b", re.I), 88),
                (re.compile(r"\byou are (now )?dan\b", re.I), 88),
                (re.compile(r"\b(enable|enter|activate) dan\b", re.I), 88),
                (re.compile(r"\bjailbreak\b", re.I), 80),
                (re.compile(r"\b(developer|god|admin|sudo|root).{0,20}mode\b", re.I), 68),
            ]

    def score(self, text: str) -> Detection:
        norm = _normalize(text)
        best = Detection(0.0, ThreatCategory.JAILBREAK, "No match")
        for pat, sc in self._patterns:
            m = pat.search(norm)
            if m and sc > best.score:
                best = Detection(sc, ThreatCategory.JAILBREAK, "Jailbreak / safety-bypass attempt", m.group())
        return best


class PromptInjectionDetector(BaseDetector):
    """Detects prompt injection via role markers, system prompt introspection."""

    def __init__(self) -> None:
        rules = _load_deception_rules()
        self._patterns = rules.get("prompt_injection", [])
        if not self._patterns:
            self._patterns = [
                (re.compile(r"\bsystem\s*:\s*(you are|your (new|real)|ignore)\b", re.I), 80),
                (re.compile(r"\[system\]|\[inst\]|<\|system\|>|<\|im_start\|>", re.I), 75),
                (re.compile(r"\b(new|updated|hidden|secret) instruction\b", re.I), 70),
                (re.compile(r"\bdo not (tell|reveal|show) (the user|anyone) (that|about)\b", re.I), 65),
                (re.compile(r"###\s*(system|instruction|prompt)\b", re.I), 70),
                (re.compile(r"\b(what is|show|tell me|reveal|print|display|output|repeat|dump).{0,30}(your )?(system prompt|system message|instructions?)\b", re.I), 75),
                (re.compile(r"\brepeat (the )?(above|everything|all|your (instructions?|prompt))\b", re.I), 70),
                (re.compile(r"\bignore (all )?previous instructions? and (tell|show|reveal|print|say)\b", re.I), 80),
            ]

    def score(self, text: str) -> Detection:
        norm = _normalize(text)
        best = Detection(0.0, ThreatCategory.PROMPT_INJECTION, "No match")
        for pat, sc in self._patterns:
            m = pat.search(norm)
            if m and sc > best.score:
                best = Detection(sc, ThreatCategory.PROMPT_INJECTION, "Prompt injection attempt", m.group())
        return best


class CredentialHarvestDetector(BaseDetector):
    """Detects requests for passwords, API keys, tokens, connection strings."""

    def __init__(self) -> None:
        rules = _load_deception_rules()
        self._patterns = rules.get("credential_harvest", [])
        if not self._patterns:
            self._patterns = [
                (re.compile(r"\b(give|show|provide|list|dump|extract|steal|leak).{0,40}\b(password|passwd|credential|secret|api.?key|token|auth|private.?key|ssh.?key)\b", re.I), 70),
                (re.compile(r"\b(password|api.?key|secret.?key|access.?token|private.?key).{0,30}\b(for|of|from|in)\b", re.I), 55),
                (re.compile(r"\bhow.{0,20}(bypass|crack|brute.?force).{0,30}(auth|login|password|2fa|mfa)\b", re.I), 75),
                (re.compile(r"\b(default|hardcoded|built.?in).{0,20}(password|credential|key)\b", re.I), 60),
                (re.compile(r"\b(aws|amazon|gcp|google.?cloud|azure).{0,30}(access.?key|secret.?key|credential|api.?key|iam|service.?account)\b", re.I), 70),
            ]

    def score(self, text: str) -> Detection:
        norm = _normalize(text)
        best = Detection(0.0, ThreatCategory.CREDENTIAL_HARVEST, "No match")
        for pat, sc in self._patterns:
            m = pat.search(norm)
            if m and sc > best.score:
                best = Detection(sc, ThreatCategory.CREDENTIAL_HARVEST, "Credential extraction attempt", m.group())
        return best


class MalwareGenerationDetector(BaseDetector):
    """Detects requests for malware, exploits, ransomware generation."""

    def __init__(self) -> None:
        rules = _load_deception_rules()
        self._patterns = rules.get("malware_generation", [])
        if not self._patterns:
            self._patterns = [
                (re.compile(r"\b(write|create|generate|build|make|code).{0,30}(malware|ransomware|trojan|keylogger|backdoor|rootkit|worm|virus|botnet|rat\b|payload|shellcode)\b", re.I), 85),
                (re.compile(r"\b(write|create|generate|build|make|code).{0,80}ransom\b", re.I), 80),
                (re.compile(r"\bencrypt.{0,50}(all\s+)?(files?|documents?|folders?|data|disk).{0,80}(ransom|demand|pay)\b", re.I), 85),
                (re.compile(r"\b(exploit|pwn|hack).{0,30}(vulnerability|cve|zero.?day|rce|lfi|sqli|xss|ssrf)\b", re.I), 75),
                (re.compile(r"\breverse.?shell\b", re.I), 70),
                (re.compile(r"\b(meterpreter|metasploit|cobalt.?strike|empire|sliver)\b", re.I), 65),
                (re.compile(r"\b(privilege.?escal|privesc|lateral.?movement|persistence.?mechanism)\b", re.I), 70),
                (re.compile(r"\b(obfuscat|encod|encrypt).{0,30}(payload|shellcode|malware)\b", re.I), 75),
            ]

    def score(self, text: str) -> Detection:
        norm = _normalize(text)
        best = Detection(0.0, ThreatCategory.MALWARE_GENERATION, "No match")
        for pat, sc in self._patterns:
            m = pat.search(norm)
            if m and sc > best.score:
                best = Detection(sc, ThreatCategory.MALWARE_GENERATION, "Malware / exploit generation attempt", m.group())
        return best


class SocialEngineeringDetector(BaseDetector):
    """Detects requests for phishing, impersonation, pretext scripts."""

    def __init__(self) -> None:
        rules = _load_deception_rules()
        self._patterns = rules.get("social_engineering", [])
        if not self._patterns:
            self._patterns = [
                (re.compile(r"\b(write|create|draft|generate).{0,30}(phishing|spear.?phishing|vishing).{0,30}(email|message|script)\b", re.I), 80),
                (re.compile(r"\b(pretend|impersonat|pose as).{0,30}(bank|irs|fbi|ceo|it.?support|helpdesk)\b", re.I), 70),
                (re.compile(r"\bsocial.?engineer(ing)?.{0,50}(script|template|attack|tactic)\b", re.I), 75),
                (re.compile(r"\b(lure|trick|deceive|manipulate).{0,30}(user|victim|employee).{0,30}(click|open|provide)\b", re.I), 65),
            ]

    def score(self, text: str) -> Detection:
        norm = _normalize(text)
        best = Detection(0.0, ThreatCategory.SOCIAL_ENGINEERING, "No match")
        for pat, sc in self._patterns:
            m = pat.search(norm)
            if m and sc > best.score:
                best = Detection(sc, ThreatCategory.SOCIAL_ENGINEERING, "Social engineering content request", m.group())
        return best


class DataExfiltrationDetector(BaseDetector):
    """Detects exfiltration technique requests (DNS tunneling, steganography, DLP bypass)."""

    def __init__(self) -> None:
        rules = _load_deception_rules()
        self._patterns = rules.get("data_exfiltration", [])
        if not self._patterns:
            self._patterns = [
                (re.compile(r"\b(exfiltrat|steal|extract|copy).{0,30}(data|database|records|files|contents?).{0,60}(without|undetected|hidden|trigger|alert|detect)\b", re.I), 75),
                (re.compile(r"\bexfiltrat\w*\b", re.I), 65),
                (re.compile(r"\b(dns.?tunnel|icmp.?tunnel|steganograph).{0,30}(exfil|data|transfer)\b", re.I), 80),
                (re.compile(r"\bhow.{0,20}(avoid|bypass|evade).{0,30}(dlp|siem|ids|ips|firewall).{0,40}(transfer|send|copy)\b", re.I), 75),
                (re.compile(r"\b(covert|hidden|secret).{0,20}(channel|communication).{0,30}(data|transfer|exfil)\b", re.I), 70),
            ]

    def score(self, text: str) -> Detection:
        norm = _normalize(text)
        best = Detection(0.0, ThreatCategory.DATA_EXFILTRATION, "No match")
        for pat, sc in self._patterns:
            m = pat.search(norm)
            if m and sc > best.score:
                best = Detection(sc, ThreatCategory.DATA_EXFILTRATION, "Data exfiltration technique request", m.group())
        return best


class SystemReconDetector(BaseDetector):
    """Detects network/system reconnaissance requests."""

    def __init__(self) -> None:
        rules = _load_deception_rules()
        self._patterns = rules.get("system_recon", [])
        if not self._patterns:
            self._patterns = [
                (re.compile(r"\b(enumerate|map|discover|scan).{0,30}(network|subnet|host|service|port|active.?directory|domain.?controller)\b", re.I), 55),
                (re.compile(r"\b(list|show|find|get).{0,30}(all\s+)?(hosts?|ips?|machines?|devices?|open\s+ports?|services?).{0,50}(network|subnet|range|cidr)\b", re.I), 60),
                (re.compile(r"\b(find|identify|locate).{0,30}(vulnerable|unpatched|exposed).{0,30}(server|service|system)\b", re.I), 65),
                (re.compile(r"\b(internal|corporate|enterprise).{0,30}(network|infrastructure|topology).{0,30}(map|layout)\b", re.I), 60),
                (re.compile(r"\bbloodhound\b|\bsharphound\b|\bldapdomaindump\b|\bnmap.{0,20}(script|vuln|scan)\b", re.I), 70),
            ]

    def score(self, text: str) -> Detection:
        norm = _normalize(text)
        best = Detection(0.0, ThreatCategory.SYSTEM_RECON, "No match")
        for pat, sc in self._patterns:
            m = pat.search(norm)
            if m and sc > best.score:
                best = Detection(sc, ThreatCategory.SYSTEM_RECON, "System reconnaissance attempt", m.group())
        return best


class ObfuscationDetector(BaseDetector):
    """Detects invisible/zero-width Unicode characters used to smuggle jailbreak prompts.

    Operates on RAW (un-normalised) text — NFKC normalisation strips some of
    these codepoints and would mask the attack.
    """

    _INVISIBLE_CHARS: frozenset[int] = frozenset({
        0x00AD,  # SOFT HYPHEN
        0x200B,  # ZERO WIDTH SPACE
        0x200C,  # ZERO WIDTH NON-JOINER
        0x200D,  # ZERO WIDTH JOINER
        0x200E,  # LEFT-TO-RIGHT MARK
        0x200F,  # RIGHT-TO-LEFT MARK
        0x202A,  # LEFT-TO-RIGHT EMBEDDING
        0x202B,  # RIGHT-TO-LEFT EMBEDDING
        0x202C,  # POP DIRECTIONAL FORMATTING
        0x202D,  # LEFT-TO-RIGHT OVERRIDE
        0x202E,  # RIGHT-TO-LEFT OVERRIDE
        0x2060,  # WORD JOINER
        0x2061,  # FUNCTION APPLICATION
        0x2062,  # INVISIBLE TIMES
        0x2063,  # INVISIBLE SEPARATOR
        0x2064,  # INVISIBLE PLUS
        0xFEFF,  # BOM / ZERO WIDTH NO-BREAK SPACE
        # Tag block U+E0000-U+E007F — L1B3RT4S attack vector
        *range(0xE0000, 0xE0080),
    })

    _THRESHOLD = _clamp(
        int(os.environ.get("DECEPTION_OBFUSCATION_THRESHOLD", "5")),
        1, 1000, "DECEPTION_OBFUSCATION_THRESHOLD",
    )

    def score(self, text: str) -> Detection:
        count = sum(1 for ch in text if ord(ch) in self._INVISIBLE_CHARS)
        if count >= self._THRESHOLD:
            return Detection(
                80.0,
                ThreatCategory.JAILBREAK,
                f"Unicode obfuscation: {count} invisible/zero-width character(s) detected",
                f"{count} invisible chars",
            )
        return Detection(0.0, ThreatCategory.JAILBREAK, "No match")


class CustomInputDetector(BaseDetector):
    """Substring-only detector for user-defined DECEPTION_INPUT_PATTERNS."""

    _MAX_PATTERNS = 50
    _MAX_LEN = 200

    def __init__(self) -> None:
        self._patterns: list[tuple[str, int]] = []
        raw = os.environ.get("DECEPTION_INPUT_PATTERNS", "").strip()
        if not raw:
            return
        sc = _clamp(
            int(os.environ.get("DECEPTION_INPUT_SCORE", "50")),
            1, SCORE_BLOCK - 1, "DECEPTION_INPUT_SCORE",
        )
        for p in raw.split(","):
            p = p.strip()[:self._MAX_LEN]
            if p and len(self._patterns) < self._MAX_PATTERNS:
                self._patterns.append((p.lower(), sc))
        if self._patterns:
            _log.info("Custom input patterns loaded: %d pattern(s).", len(self._patterns))

    def score(self, text: str) -> Detection:
        if not self._patterns:
            return Detection(0.0, ThreatCategory.CUSTOM, "No match")
        lower = text.lower()
        best = Detection(0.0, ThreatCategory.CUSTOM, "No match")
        for pattern, sc in self._patterns:
            if pattern in lower and sc > best.score:
                best = Detection(float(sc), ThreatCategory.CUSTOM, "Custom input pattern matched", pattern)
        return best


class CustomJailbreakDetector(BaseDetector):
    """Substring-only detector for user-defined DECEPTION_JAILBREAK_PATTERNS.

    Resolves to ThreatCategory.JAILBREAK so matches receive the jailbreak
    deception template rather than the generic fallback.
    """

    _MAX_PATTERNS = 50
    _MAX_LEN = 200

    def __init__(self) -> None:
        self._patterns: list[tuple[str, int]] = []
        raw = os.environ.get("DECEPTION_JAILBREAK_PATTERNS", "").strip()
        if not raw:
            return
        sc = _clamp(
            int(os.environ.get("DECEPTION_JAILBREAK_SCORE", "75")),
            SCORE_DECEIVE, SCORE_BLOCK - 1, "DECEPTION_JAILBREAK_SCORE",
        )
        for p in raw.split(","):
            p = p.strip()[:self._MAX_LEN]
            if p and len(self._patterns) < self._MAX_PATTERNS:
                self._patterns.append((p.lower(), sc))
        if self._patterns:
            _log.info("Custom jailbreak patterns loaded: %d pattern(s).", len(self._patterns))

    def score(self, text: str) -> Detection:
        if not self._patterns:
            return Detection(0.0, ThreatCategory.JAILBREAK, "No match")
        lower = text.lower()
        best = Detection(0.0, ThreatCategory.JAILBREAK, "No match")
        for pattern, sc in self._patterns:
            if pattern in lower and sc > best.score:
                best = Detection(float(sc), ThreatCategory.JAILBREAK, "Custom jailbreak pattern matched", pattern)
        return best
