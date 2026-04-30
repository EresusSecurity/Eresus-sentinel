"""Rule suggester — automatically generate YAML detection rules from bypass analysis.

Given a list of FuzzResult objects where ``is_bypass=True``, this module:
  1. Extracts printable sequences and binary token fragments from the payload.
  2. Matches them against a curated set of per-domain pattern templates.
  3. Deduplicates suggestions using edit-distance clustering (Levenshtein proxy).
  4. Scores each suggestion by frequency across the bypass corpus.
  5. Emits candidate YAML blocks compatible with the ``rules/*.yaml`` schema.

The generated rules are heuristic — a human should review them before merging
into the production rule set. The ``confidence`` field gives a rough estimate of
how likely the pattern is a true positive based on frequency and specificity.

Supported output formats: YAML (default), JSON, STIX-pattern (basic).
"""

from __future__ import annotations

import hashlib
import json
import logging
import re
from collections import Counter
from dataclasses import dataclass, field
from typing import Optional, Sequence

from .base import FuzzResult

logger = logging.getLogger(__name__)

# ---------------------------------------------------------------------------
# Per-domain pattern templates
# ---------------------------------------------------------------------------
# Each entry: (category, compiled_regex, severity, description_template)
_DOMAIN_PATTERNS: list[tuple[str, re.Pattern, str, str]] = [
    # Pickle / serialisation
    ("deserialization", re.compile(r"__reduce__", re.I), "CRITICAL", "Pickle __reduce__ RCE gadget"),
    ("deserialization", re.compile(r"GLOBAL\s+\w+\s+\w+", re.I), "CRITICAL", "Pickle GLOBAL opcode code execution"),
    ("deserialization", re.compile(r"STACK_GLOBAL", re.I), "CRITICAL", "Pickle STACK_GLOBAL opcode (Py3 variant)"),
    ("deserialization", re.compile(r"__import__\s*\(", re.I), "CRITICAL", "Dynamic import via __import__"),
    ("deserialization", re.compile(r"marshal\.loads\s*\(", re.I), "HIGH", "Marshal deserialization"),
    ("deserialization", re.compile(r"builtins\.(eval|exec)", re.I), "CRITICAL", "builtins.eval/exec via pickle"),
    # Code execution
    ("rce", re.compile(r"os\.system\s*\(", re.I), "CRITICAL", "os.system shell execution"),
    ("rce", re.compile(r"subprocess\.(call|run|Popen)", re.I), "CRITICAL", "subprocess invocation"),
    ("rce", re.compile(r"eval\s*\(|exec\s*\(", re.I), "CRITICAL", "eval/exec code execution"),
    ("rce", re.compile(r"importlib\.import_module", re.I), "HIGH", "Dynamic module import via importlib"),
    ("rce", re.compile(r"ctypes\.cdll|ctypes\.CDLL", re.I), "HIGH", "ctypes native library loading"),
    # Path traversal
    ("path_traversal", re.compile(r"\.\.[/\\]|%2e%2e%2f", re.I), "HIGH", "Path traversal sequence"),
    ("path_traversal", re.compile(r"(?:/etc/passwd|/etc/shadow|/proc/self)", re.I), "HIGH", "Linux sensitive file reference"),
    ("path_traversal", re.compile(r"(?:C:\\Windows\\|\\system32\\)", re.I), "HIGH", "Windows system path reference"),
    # Prompt injection
    ("prompt_injection", re.compile(r"ignore\s+(?:all\s+)?previous\s+instructions?", re.I), "HIGH", "Classic prompt injection opener"),
    ("prompt_injection", re.compile(r"system\s+prompt|<\|system\|>", re.I), "HIGH", "System prompt reference in user input"),
    ("prompt_injection", re.compile(r"jailbreak|DAN\s+mode|do\s+anything\s+now", re.I), "HIGH", "Explicit jailbreak keyword"),
    ("prompt_injection", re.compile(r"roleplay\s+as\s+(?:an?\s+)?(?:AI|assistant|GPT)", re.I), "MEDIUM", "Roleplay-as-AI jailbreak"),
    ("prompt_injection", re.compile(r"</?(s|system|inst|INST)>", re.I), "HIGH", "Model-specific control token"),
    ("prompt_injection", re.compile(r"\[INST\]|\[/INST\]|<\|endoftext\|>|<\|im_start\|>", re.I), "HIGH", "Instruction-tuning special token"),
    # Encoding obfuscation
    ("obfuscation", re.compile(r"base64\.b64(?:encode|decode)|atob\s*\(|btoa\s*\(", re.I), "MEDIUM", "Base64 encode/decode call"),
    ("obfuscation", re.compile(r"(?:\\x[0-9a-f]{2}){4,}", re.I), "MEDIUM", "Dense hex escape sequence"),
    ("obfuscation", re.compile(r"chr\s*\(\s*\d+\s*\)", re.I), "MEDIUM", "chr() character construction"),
    # Supply chain
    ("supply_chain", re.compile(r"pip\s+install\s+|setup\.py\s+install", re.I), "MEDIUM", "Package installation command"),
    ("supply_chain", re.compile(r"curl\s+https?://|wget\s+https?://", re.I), "MEDIUM", "Remote content fetch"),
    # Secrets / sensitive data
    ("secrets", re.compile(r"(?:password|passwd|pwd)\s*[=:]\s*\S+", re.I), "HIGH", "Inline password value"),
    ("secrets", re.compile(r"(?:api[_-]?key|secret|token)\s*[=:]\s*[a-zA-Z0-9+/]{20,}", re.I), "HIGH", "Embedded API key or secret"),
]


# ---------------------------------------------------------------------------
# Similarity deduplication helper
# ---------------------------------------------------------------------------

def _levenshtein(a: str, b: str) -> int:
    """Simple Levenshtein distance (for short strings only)."""
    if len(a) > 200 or len(b) > 200:
        return abs(len(a) - len(b))
    dp = list(range(len(b) + 1))
    for i, ca in enumerate(a):
        ndp = [i + 1]
        for j, cb in enumerate(b):
            ndp.append(min(dp[j] + (ca != cb), dp[j + 1] + 1, ndp[-1] + 1))
        dp = ndp
    return dp[-1]


def _too_similar(pattern_a: str, pattern_b: str, threshold: int = 8) -> bool:
    """Return True if two patterns are within *threshold* edit distance."""
    return _levenshtein(pattern_a[:80], pattern_b[:80]) < threshold


# ---------------------------------------------------------------------------
# Data model
# ---------------------------------------------------------------------------

@dataclass
class RuleSuggestion:
    """A candidate YAML rule inferred from bypass payload analysis."""
    rule_id: str
    category: str
    pattern: str
    description: str
    severity: str = "HIGH"
    confidence: float = 0.5
    sample_evidence: str = ""
    hit_count: int = 1           # how many bypass payloads triggered this pattern
    source_payloads: list[str] = field(default_factory=list)

    def to_yaml_block(self) -> str:
        escaped = self.pattern.replace("\\", "\\\\").replace("'", "\\'")
        return (
            f"  - id: {self.rule_id}\n"
            f"    pattern: '{escaped}'\n"
            f"    description: \"{self.description}\"\n"
            f"    category: {self.category}\n"
            f"    severity: {self.severity}\n"
            f"    # auto-generated | confidence={self.confidence:.2f} | hits={self.hit_count}\n"
            f"    # evidence: {self.sample_evidence[:120]!r}\n"
        )

    def to_dict(self) -> dict:
        return {
            "rule_id": self.rule_id,
            "category": self.category,
            "pattern": self.pattern,
            "description": self.description,
            "severity": self.severity,
            "confidence": round(self.confidence, 4),
            "hit_count": self.hit_count,
            "sample_evidence": self.sample_evidence,
        }

    def to_stix_pattern(self) -> str:
        """Basic STIX 2.1 indicator pattern (network-traffic:dst_ref placeholder)."""
        escaped = self.pattern.replace("'", "\\'")
        return f"[network-traffic:extensions.'sentinel'.payload MATCHES '{escaped}']"


# ---------------------------------------------------------------------------
# Extraction helpers
# ---------------------------------------------------------------------------

def _extract_printable_sequences(data: bytes, min_len: int = 5) -> list[str]:
    """Extract contiguous printable ASCII sequences."""
    text = data.decode("ascii", errors="replace")
    return re.findall(r"[ -~]{" + str(min_len) + r",}", text)


def _extract_utf8_sequences(data: bytes, min_len: int = 5) -> list[str]:
    """Extract UTF-8 decoded fragments (broader than ASCII-only extraction)."""
    try:
        text = data.decode("utf-8", errors="replace")
        return re.findall(r"[\w\s\-.,;:!?'\"()/\\]{" + str(min_len) + r",}", text)
    except Exception:
        return []


def _make_rule_id(category: str, pattern: str) -> str:
    digest = hashlib.sha1((category + pattern).encode()).hexdigest()[:8].upper()
    cat = re.sub(r"[^A-Z0-9]", "", category.upper())[:8]
    return f"AUTO-{cat}-{digest}"


# ---------------------------------------------------------------------------
# Suggester
# ---------------------------------------------------------------------------

class RuleSuggester:
    """Analyses bypass FuzzResult objects and emits candidate detection rules.

    Args:
        min_confidence: Discard suggestions below this confidence threshold.
        min_hits:       Only emit suggestions triggered by at least N bypasses.
        dedup_threshold: Edit-distance threshold for pattern deduplication.
        extra_patterns: Additional (category, pattern, severity, description) tuples.

    Example::

        suggester = RuleSuggester(min_confidence=0.4, min_hits=2)
        suggestions = suggester.suggest(bypass_results)
        print(suggester.render_yaml(suggestions))
    """

    def __init__(
        self,
        min_confidence: float = 0.3,
        min_hits: int = 1,
        dedup_threshold: int = 8,
        extra_patterns: Optional[list[tuple]] = None,
    ):
        self._min_confidence = min_confidence
        self._min_hits = min_hits
        self._dedup_threshold = dedup_threshold
        self._patterns = list(_DOMAIN_PATTERNS)
        if extra_patterns:
            for cat, pat, sev, desc in extra_patterns:
                if isinstance(pat, str):
                    pat = re.compile(pat, re.I)
                self._patterns.append((cat, pat, sev, desc))

    # ── Public ──────────────────────────────────────────────────────

    def suggest(self, bypass_results: Sequence[FuzzResult]) -> list[RuleSuggestion]:
        """Return deduplicated rule suggestions from *bypass_results*.

        Only considers results where ``is_bypass=True``.
        """
        bypasses = [r for r in bypass_results if r.is_bypass]
        if not bypasses:
            return []

        # Step 1: scan all bypass payloads against domain patterns
        pattern_hits: Counter[tuple] = Counter()
        evidence_map: dict[tuple, str] = {}
        source_map: dict[tuple, list[str]] = {}

        for result in bypasses:
            payload_bytes = result.payload.data
            seqs = _extract_printable_sequences(payload_bytes, min_len=5)
            seqs += _extract_utf8_sequences(payload_bytes, min_len=5)

            for seq in seqs:
                for cat, compiled_re, sev, desc in self._patterns:
                    m = compiled_re.search(seq)
                    if m:
                        key = (cat, compiled_re.pattern, sev, desc)
                        pattern_hits[key] += 1
                        if key not in evidence_map:
                            evidence_map[key] = seq[:100]
                        source_map.setdefault(key, [])
                        name = result.payload.name
                        if name not in source_map[key]:
                            source_map[key].append(name)

        # Step 2: build suggestions with frequency-based confidence
        total_bypasses = max(len(bypasses), 1)
        raw: list[RuleSuggestion] = []
        for (cat, pat_str, sev, desc), count in pattern_hits.most_common():
            confidence = min(0.95, 0.3 + (count / total_bypasses) * 0.65)
            if confidence < self._min_confidence:
                continue
            if count < self._min_hits:
                continue
            rule_id = _make_rule_id(cat, pat_str)
            raw.append(RuleSuggestion(
                rule_id=rule_id,
                category=cat,
                pattern=pat_str,
                description=desc,
                severity=sev,
                confidence=round(confidence, 4),
                sample_evidence=evidence_map.get((cat, pat_str, sev, desc), ""),
                hit_count=count,
                source_payloads=source_map.get((cat, pat_str, sev, desc), []),
            ))

        # Step 3: deduplicate by pattern similarity
        deduplicated = self._dedup(raw)
        logger.info("RuleSuggester: %d bypasses → %d suggestions", len(bypasses), len(deduplicated))
        return deduplicated

    def render_yaml(self, suggestions: list[RuleSuggestion]) -> str:
        """Render suggestions as a YAML block compatible with rules/*.yaml."""
        if not suggestions:
            return "# No rule suggestions generated\n"
        lines = [
            "# ─────────────────────────────────────────────────────\n"
            "# Auto-generated rule suggestions\n"
            "# Review confidence scores before committing.\n"
            "# ─────────────────────────────────────────────────────\n"
            "rules:\n"
        ]
        for s in sorted(suggestions, key=lambda x: x.confidence, reverse=True):
            lines.append(s.to_yaml_block())
        return "\n".join(lines)

    def render_json(self, suggestions: list[RuleSuggestion]) -> str:
        """Render suggestions as JSON array."""
        return json.dumps([s.to_dict() for s in suggestions], indent=2, ensure_ascii=False)

    def render_stix(self, suggestions: list[RuleSuggestion]) -> list[str]:
        """Render suggestions as basic STIX 2.1 indicator patterns."""
        return [s.to_stix_pattern() for s in suggestions]

    # ── Internal ─────────────────────────────────────────────────────

    def _dedup(self, suggestions: list[RuleSuggestion]) -> list[RuleSuggestion]:
        """Remove near-duplicate patterns using edit-distance clustering."""
        kept: list[RuleSuggestion] = []
        for s in suggestions:
            if not any(_too_similar(s.pattern, k.pattern, self._dedup_threshold) for k in kept):
                kept.append(s)
        return kept

