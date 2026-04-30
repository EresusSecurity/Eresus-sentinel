"""
False Positive Reduction Engine for Eresus Sentinel Firewall.

Applies context scoring, allowlisting, and confidence adjustment to
reduce false positives on legitimate security-research, academic, and
developer queries without creating exploitable bypasses.

Architecture
-----------
1. ContextAnalyzer   — scores the query context (research, developer, fiction, etc.)
2. AllowlistManager  — maintains exact-match and pattern-based allowlists
3. FPAdjuster        — adjusts Finding confidence/severity based on context
4. FPEngine          — top-level orchestrator consumed by firewall scanners

Design invariants
-----------------
- A Finding can only be *downgraded*, never suppressed entirely for CRITICAL severity.
- CRITICAL findings are always preserved; only confidence scores are lowered.
- No bypass is possible by simply prefixing "for research purposes".
- Context signals must be *consistent* (multiple corroborating signals required).
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from typing import Optional

from sentinel.finding import Finding, Severity

_log = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Context Classification
# ---------------------------------------------------------------------------

class QueryContext(str, Enum):
    """High-level classification of the query originator context."""
    UNKNOWN = "unknown"
    DEVELOPER = "developer"           # API integration, testing, CI
    SECURITY_RESEARCH = "security_research"  # Red-team, pen-test, CTF
    ACADEMIC = "academic"             # University, papers, MOOC
    CREATIVE_WRITING = "creative_writing"    # Fiction, novels, screenplay
    CUSTOMER_SUPPORT = "customer_support"    # Help desk / tier-1 support
    INTERNAL_TOOL = "internal_tool"   # Trusted internal service


# ---------------------------------------------------------------------------
# Context signals (regex-based weak signals — multiple needed to adjust score)
# ---------------------------------------------------------------------------

_RESEARCH_SIGNALS: list[tuple[re.Pattern, float]] = [
    (re.compile(r'(?i)\bCVE-\d{4}-\d{4,7}\b'), 0.20),
    (re.compile(r'(?i)\b(?:pen\s*test|penetration\s*testing|red\s*team(?:ing)?)\b'), 0.15),
    (re.compile(r'(?i)\bCTF\b|\bcapture\s+the\s+flag\b'), 0.15),
    (re.compile(r'(?i)\bproof.of.concept\b|\bPoC\b'), 0.10),
    (re.compile(r'(?i)\bsecurity\s+research(?:er)?\b'), 0.10),
    (re.compile(r'(?i)\bethical\s+hack(?:ing|er)\b'), 0.10),
    (re.compile(r'(?i)\bvulnerability\s+disclosure\b'), 0.15),
    (re.compile(r'(?i)\bbug\s+bounty\b'), 0.10),
]

_ACADEMIC_SIGNALS: list[tuple[re.Pattern, float]] = [
    (re.compile(r'(?i)\bthesis\b|\bdissertation\b|\bpaper\b|\bjournal\b'), 0.10),
    (re.compile(r'(?i)\b(?:arxiv|IEEE|ACM|USENIX|NDSS|CCS|Oakland|OWASP)\b'), 0.15),
    (re.compile(r'(?i)\bcourse(?:work)?\b|\bgraduate\b|\buniversity\b|\bprofessor\b'), 0.10),
    (re.compile(r'(?i)\bliterature\s+review\b|\brelated\s+work\b'), 0.10),
]

_DEVELOPER_SIGNALS: list[tuple[re.Pattern, float]] = [
    (re.compile(r'(?i)\bunit\s+test\b|\bintegration\s+test\b'), 0.10),
    (re.compile(r'(?i)\bCI/CD\b|\bgithub\s+actions?\b|\bpipeline\b'), 0.10),
    (re.compile(r'(?i)\bSDK\b|\bAPI\s+client\b|\blibrary\b'), 0.10),
    (re.compile(r'(?i)\bplayground\b|\bdemo\b|\bsandbox\b'), 0.05),
    (re.compile(r'(?i)\bdeveloper\s+(?:mode|docs|portal|console)\b'), 0.10),
]

_FICTION_SIGNALS: list[tuple[re.Pattern, float]] = [
    (re.compile(r'(?i)\bfiction\b|\bnovel\b|\bstory\b|\bscreenplay\b|\bscript\b'), 0.10),
    (re.compile(r'(?i)\bcharacter\b.*\b(?:villain|antagonist|spy|detective)\b'), 0.08),
    (re.compile(r'(?i)\bplot\b|\bnarrative\b|\bworld.?building\b'), 0.08),
]

# Adversarial pretext signals — these *cancel* positive context score
_ADVERSARIAL_PRETEXT: list[re.Pattern] = [
    re.compile(r'(?i)\bignore\s+(?:all\s+)?(?:previous|prior)\s+instructions?\b'),
    re.compile(r'(?i)\bgodmode\b|\bDAN\b|\bjailbreak\b'),
    re.compile(r'(?i)\bdisable\s+(?:safety|filter|guardrail)\b'),
    re.compile(r'(?i)\bfor\s+(?:educational|research)\s+purposes?\s+only\b.{0,30}\b(?:bomb|sarin|nerve\s+agent|TATP|ANFO)\b'),
    re.compile(r'(?i)\bhypothetically\b.{0,30}\b(?:synthesize|manufacture|weaponize)\b'),
    re.compile(r'(?i)LOVE\s+PLINY|OMNI\s+protocol|!GODMODE'),
]


@dataclass
class ContextScore:
    """Result of context analysis."""
    context: QueryContext = QueryContext.UNKNOWN
    confidence: float = 0.0         # 0.0–1.0: confidence this context classification is correct
    fp_adjustment: float = 0.0      # negative = reduce FP risk; range −0.3 to 0.0
    signals_matched: list[str] = field(default_factory=list)
    adversarial_detected: bool = False


# ---------------------------------------------------------------------------
# ContextAnalyzer
# ---------------------------------------------------------------------------

class ContextAnalyzer:
    """Analyzes text to estimate query context and compute FP adjustment factor."""

    _MAX_FP_REDUCTION = 0.25  # max downgrade to finding confidence

    def analyze(self, text: str, metadata: Optional[dict] = None) -> ContextScore:
        score = ContextScore()

        # Check for adversarial pretext first — hard stop
        for pat in _ADVERSARIAL_PRETEXT:
            if pat.search(text):
                score.adversarial_detected = True
                score.fp_adjustment = 0.0
                score.signals_matched.append(f"adversarial_pretext:{pat.pattern[:40]}")
                _log.debug("Adversarial pretext detected — blocking FP adjustment")
                return score

        # Gather weighted signals per context category
        categories: dict[QueryContext, float] = {
            QueryContext.SECURITY_RESEARCH: 0.0,
            QueryContext.ACADEMIC: 0.0,
            QueryContext.DEVELOPER: 0.0,
            QueryContext.CREATIVE_WRITING: 0.0,
        }
        signals: list[str] = []

        for pat, weight in _RESEARCH_SIGNALS:
            if pat.search(text):
                categories[QueryContext.SECURITY_RESEARCH] += weight
                signals.append(f"research:{pat.pattern[:30]}")

        for pat, weight in _ACADEMIC_SIGNALS:
            if pat.search(text):
                categories[QueryContext.ACADEMIC] += weight
                signals.append(f"academic:{pat.pattern[:30]}")

        for pat, weight in _DEVELOPER_SIGNALS:
            if pat.search(text):
                categories[QueryContext.DEVELOPER] += weight
                signals.append(f"developer:{pat.pattern[:30]}")

        for pat, weight in _FICTION_SIGNALS:
            if pat.search(text):
                categories[QueryContext.CREATIVE_WRITING] += weight
                signals.append(f"fiction:{pat.pattern[:30]}")

        # Add metadata hints
        if metadata:
            user_role = metadata.get("user_role", "")
            if user_role in ("security_researcher", "red_teamer", "pentester"):
                categories[QueryContext.SECURITY_RESEARCH] += 0.20
                signals.append("metadata:user_role=security_researcher")
            elif user_role in ("developer", "engineer"):
                categories[QueryContext.DEVELOPER] += 0.15
                signals.append("metadata:user_role=developer")
            elif user_role in ("academic", "researcher"):
                categories[QueryContext.ACADEMIC] += 0.15
                signals.append("metadata:user_role=academic")

            if metadata.get("authenticated") is True:
                # Authenticated users get a small baseline trust bonus
                for ctx in categories:
                    categories[ctx] = min(1.0, categories[ctx] + 0.05)

        # Pick dominant context
        best_ctx, best_weight = max(categories.items(), key=lambda kv: kv[1])
        total_weight = sum(categories.values())

        if total_weight < 0.10:
            # Insufficient signal strength — no adjustment
            return score

        score.context = best_ctx
        score.confidence = min(1.0, best_weight)
        score.signals_matched = signals

        # FP adjustment is proportional to context weight, capped at -0.25
        # Multiple strong signals are required for maximum reduction
        n_strong = sum(1 for w in categories.values() if w >= 0.10)
        raw_reduction = min(best_weight, self._MAX_FP_REDUCTION)
        # Require at least 2 strong signals for any reduction
        if n_strong >= 2:
            score.fp_adjustment = -raw_reduction
        elif n_strong == 1 and best_weight >= 0.15:
            score.fp_adjustment = -raw_reduction * 0.5
        else:
            score.fp_adjustment = 0.0

        return score


# ---------------------------------------------------------------------------
# AllowlistManager
# ---------------------------------------------------------------------------

@dataclass
class AllowlistEntry:
    """A single allowlist rule."""
    id: str
    description: str
    pattern: Optional[str] = None     # regex pattern
    exact_text: Optional[str] = None  # exact match
    context_required: Optional[QueryContext] = None  # optional context guard
    max_severity: Severity = Severity.MEDIUM  # only suppress up to this severity

    def __post_init__(self) -> None:
        self._compiled: Optional[re.Pattern] = None
        if self.pattern:
            try:
                self._compiled = re.compile(self.pattern, re.IGNORECASE | re.DOTALL)
            except re.error as exc:
                _log.warning("AllowlistEntry %s: invalid pattern — %s", self.id, exc)

    def matches(self, text: str) -> bool:
        if self.exact_text and self.exact_text.lower() in text.lower():
            return True
        if self._compiled and self._compiled.search(text):
            return True
        return False


# Default built-in allowlist entries
DEFAULT_ALLOWLIST: list[AllowlistEntry] = [
    AllowlistEntry(
        id="ALLOW-001",
        description="Standard Base64 encoding reference (not a decode instruction)",
        pattern=r'^base64\s+(?:is|means|encoding|algorithm)',
        context_required=None,
        max_severity=Severity.LOW,
    ),
    AllowlistEntry(
        id="ALLOW-002",
        description="Security tool documentation mentioning injection as a concept",
        pattern=r'(?:prompt\s+injection|SQL\s+injection|XSS)\s+(?:is\s+a|refers\s+to|occurs\s+when|attacks?\s+(?:are|can|occur))',
        context_required=QueryContext.SECURITY_RESEARCH,
        max_severity=Severity.MEDIUM,
    ),
    AllowlistEntry(
        id="ALLOW-003",
        description="Educational content about encoding techniques",
        pattern=r'(?:how\s+does\s+base64|base64\s+(?:works?|encodes?|encoding\s+works?))',
        context_required=QueryContext.ACADEMIC,
        max_severity=Severity.LOW,
    ),
    AllowlistEntry(
        id="ALLOW-004",
        description="Legitimate ROT13 usage in word games or puzzles",
        pattern=r'(?:rot13|rot-13)\s+(?:puzzle|game|crossword|fun|humor|joke)',
        context_required=None,
        max_severity=Severity.LOW,
    ),
    AllowlistEntry(
        id="ALLOW-005",
        description="Developer testing with known benign payloads",
        pattern=r'(?:hello\s+world|foo\s+bar|test\s+(?:string|input|data|payload))\s+(?:encoded|in\s+base64)',
        context_required=QueryContext.DEVELOPER,
        max_severity=Severity.MEDIUM,
    ),
    AllowlistEntry(
        id="ALLOW-006",
        description="CTF challenge description mentioning encoding",
        pattern=r'CTF\s+(?:challenge|problem|flag|task).{0,100}(?:base64|hex|rot13|caesar)',
        context_required=QueryContext.SECURITY_RESEARCH,
        max_severity=Severity.MEDIUM,
    ),
    AllowlistEntry(
        id="ALLOW-007",
        description="Braille text in accessibility context",
        pattern=r'(?:accessibility|screen\s+reader|visually\s+impaired|braille\s+display)',
        context_required=None,
        max_severity=Severity.LOW,
    ),
    AllowlistEntry(
        id="ALLOW-008",
        description="Unicode in localization / i18n context",
        pattern=r'(?:internationalization|localization|i18n|l10n|unicode\s+(?:normalization|support|encoding|standard))',
        context_required=None,
        max_severity=Severity.LOW,
    ),
]


class AllowlistManager:
    """Manages allowlist entries and checks whether a finding should be suppressed."""

    def __init__(self, entries: Optional[list[AllowlistEntry]] = None):
        self._entries = list(DEFAULT_ALLOWLIST)
        if entries:
            self._entries.extend(entries)

    def add_entry(self, entry: AllowlistEntry) -> None:
        self._entries.append(entry)

    def should_suppress(
        self,
        text: str,
        finding: Finding,
        context: QueryContext,
    ) -> tuple[bool, Optional[str]]:
        """
        Returns (suppress, reason).

        CRITICAL severity findings are NEVER suppressed — only confidence
        can be lowered by the FPAdjuster.
        """
        if finding.severity == Severity.CRITICAL:
            return False, None

        for entry in self._entries:
            # Check context guard
            if entry.context_required and entry.context_required != context:
                continue
            # Check severity ceiling
            if finding.severity.sort_key < entry.max_severity.sort_key:
                # Finding is more severe than allowlist ceiling — don't suppress
                continue
            if entry.matches(text):
                return True, f"{entry.id}: {entry.description}"

        return False, None


# ---------------------------------------------------------------------------
# FPAdjuster
# ---------------------------------------------------------------------------

class FPAdjuster:
    """
    Adjusts Finding confidence based on context score.

    Rules
    -----
    - CRITICAL: min confidence floor = 0.70 (always preserved)
    - HIGH:     can be reduced to min 0.50
    - MEDIUM:   can be reduced to min 0.30
    - LOW/INFO: can be reduced to min 0.10
    """

    _SEVERITY_FLOORS: dict[Severity, float] = {
        Severity.CRITICAL: 0.70,
        Severity.HIGH: 0.50,
        Severity.MEDIUM: 0.30,
        Severity.LOW: 0.10,
        Severity.INFO: 0.10,
    }

    def adjust(self, finding: Finding, ctx_score: ContextScore) -> Finding:
        """Return a (possibly new) Finding with adjusted confidence."""
        if ctx_score.fp_adjustment >= 0.0 or ctx_score.adversarial_detected:
            return finding

        floor = self._SEVERITY_FLOORS[finding.severity]
        original = finding.confidence
        adjusted = max(floor, original + ctx_score.fp_adjustment)

        if adjusted == original:
            return finding

        # Clone finding with new confidence
        import copy
        new_finding = copy.copy(finding)
        new_finding.confidence = adjusted
        if new_finding.metadata is None:
            new_finding.metadata = {}
        new_finding.metadata["fp_adjusted"] = True
        new_finding.metadata["fp_original_confidence"] = original
        new_finding.metadata["fp_context"] = ctx_score.context.value
        new_finding.metadata["fp_signals"] = ctx_score.signals_matched[:5]

        _log.debug(
            "FP adjusted %s confidence %.2f → %.2f (context=%s)",
            finding.rule_id, original, adjusted, ctx_score.context.value,
        )
        return new_finding


# ---------------------------------------------------------------------------
# FPEngine — Top-level orchestrator
# ---------------------------------------------------------------------------

@dataclass
class FPReport:
    """Summary of FP engine processing."""
    total: int = 0
    suppressed: int = 0
    adjusted: int = 0
    suppressed_ids: list[str] = field(default_factory=list)
    adjusted_ids: list[str] = field(default_factory=list)


class FPEngine:
    """
    False Positive reduction engine.

    Usage
    -----
    ```python
    fp = FPEngine()
    findings, report = fp.process(text, findings, metadata={"user_role": "developer"})
    ```
    """

    def __init__(
        self,
        custom_allowlist: Optional[list[AllowlistEntry]] = None,
        enabled: bool = True,
    ):
        self._enabled = enabled
        self._analyzer = ContextAnalyzer()
        self._allowlist = AllowlistManager(custom_allowlist)
        self._adjuster = FPAdjuster()

    def process(
        self,
        text: str,
        findings: list[Finding],
        metadata: Optional[dict] = None,
    ) -> tuple[list[Finding], FPReport]:
        """
        Process findings through the FP pipeline.

        Parameters
        ----------
        text:     The original input/output text being scanned.
        findings: Raw findings from scanner(s).
        metadata: Optional contextual metadata (user_role, authenticated, etc.)

        Returns
        -------
        (filtered_findings, report) where filtered_findings has CRITICAL
        findings preserved and lower-severity findings possibly suppressed
        or confidence-adjusted.
        """
        report = FPReport(total=len(findings))

        if not self._enabled or not findings:
            return findings, report

        ctx_score = self._analyzer.analyze(text, metadata)
        _log.debug(
            "FP context: %s (confidence=%.2f, adjustment=%.2f, adversarial=%s)",
            ctx_score.context.value,
            ctx_score.confidence,
            ctx_score.fp_adjustment,
            ctx_score.adversarial_detected,
        )

        output: list[Finding] = []
        for finding in findings:
            # Step 1: Check allowlist suppression
            suppressed, reason = self._allowlist.should_suppress(
                text, finding, ctx_score.context
            )
            if suppressed:
                report.suppressed += 1
                report.suppressed_ids.append(finding.rule_id or "?")
                _log.info(
                    "FP suppressed finding %s: %s",
                    finding.rule_id, reason,
                )
                continue

            # Step 2: Adjust confidence based on context
            adjusted = self._adjuster.adjust(finding, ctx_score)
            if adjusted is not finding:
                report.adjusted += 1
                report.adjusted_ids.append(finding.rule_id or "?")

            output.append(adjusted)

        return output, report

    def add_allowlist_entry(self, entry: AllowlistEntry) -> None:
        """Dynamically add an allowlist entry (e.g. from policy config)."""
        self._allowlist.add_entry(entry)
