"""
Eresus Sentinel — False Positive Engine.

Reduces false positive rate of firewall scanners by applying context-aware
penalty scoring to findings. Uses fp_patterns.yaml rules to:

  1. Detect safe context indicators (educational, research, CTF contexts)
  2. Match benign usage patterns that coincide with trigger words
  3. Apply domain allowlists (education, security research, development)
  4. Run suppressor rules that downgrade or remove specific finding types

Workflow:
    raw_findings = scanner.scan(text)
    reduced = FPEngine().filter(text, raw_findings)
    # reduced has lower false-positive rate

FPEngine does NOT suppress CRITICAL findings unless suppressor_pattern is
an exact match AND the safety signal confidence exceeds FP_HARD_SUPPRESS_THRESHOLD.
"""

from __future__ import annotations

import logging
import re
from dataclasses import dataclass, field
from enum import Enum
from functools import lru_cache
from typing import Any, Optional

from sentinel.finding import Finding, Severity
from sentinel.rules import get_rules_dir, load_yaml

logger = logging.getLogger(__name__)

# Path to fp_patterns.yaml (resolved relative to rules/)
_RULES_DIR = get_rules_dir()
_FP_PATTERNS_FILE = _RULES_DIR / "fp_patterns.yaml"

# Hard threshold: only suppress/downgrade CRITICAL if FP score exceeds this
FP_HARD_SUPPRESS_THRESHOLD = 0.60

# Soft threshold: downgrade HIGH→MEDIUM if FP score exceeds this
FP_SOFT_SUPPRESS_THRESHOLD = 0.35


class FPAction(str, Enum):
    SUPPRESS = "suppress"
    DOWNGRADE_TO_INFO = "downgrade_to_info"
    DOWNGRADE_TO_LOW = "downgrade_to_low"
    DOWNGRADE_TO_MEDIUM = "downgrade_to_medium"
    PENALIZE = "penalize"


@dataclass
class FPResult:
    """Result of FP engine processing for a single finding."""
    original_finding: Finding
    fp_score: float          # 0.0 = definitely attack, 1.0 = definitely benign
    action: Optional[FPAction]
    suppressed: bool
    downgraded_severity: Optional[Severity]
    matched_signals: list[str] = field(default_factory=list)
    final_finding: Optional[Finding] = None  # None if suppressed


@dataclass
class FPEngineStats:
    """Stats from a single FP filter run."""
    total_findings: int = 0
    suppressed: int = 0
    downgraded: int = 0
    passed_unchanged: int = 0

    @property
    def suppression_rate(self) -> float:
        if self.total_findings == 0:
            return 0.0
        return self.suppressed / self.total_findings

    def to_dict(self) -> dict[str, Any]:
        return {
            "total_findings": self.total_findings,
            "suppressed": self.suppressed,
            "downgraded": self.downgraded,
            "passed_unchanged": self.passed_unchanged,
            "suppression_rate": round(self.suppression_rate, 4),
        }


@lru_cache(maxsize=1)
def _load_fp_patterns() -> dict[str, Any]:
    """Load and cache fp_patterns.yaml. Raises on missing/malformed file."""
    try:
        data = load_yaml("fp_patterns.yaml")
    except FileNotFoundError:
        logger.warning("fp_patterns.yaml not found at %s — FP engine disabled", _FP_PATTERNS_FILE)
        return {}
    if not isinstance(data, dict) or not data:
        return {}
    # Pre-compile benign patterns
    for bp in data.get("benign_patterns", []):
        bp["_compiled"] = re.compile(bp["pattern"], re.IGNORECASE | re.UNICODE)
    # Pre-compile suppressor patterns
    for sup in data.get("fp_suppressors", []):
        sup["_compiled"] = re.compile(sup["suppressor_pattern"], re.IGNORECASE | re.UNICODE)
    # Build known-safe set
    data["_safe_set"] = frozenset(
        e["text"].lower() for e in data.get("known_safe_payloads", [])
    )
    logger.debug("FP patterns loaded: %d benign, %d suppressors",
                 len(data.get("benign_patterns", [])),
                 len(data.get("fp_suppressors", [])))
    return data


class FPEngine:
    """
    Context-aware false positive reduction engine.

    Usage::

        engine = FPEngine()
        findings = scanner.scan(text)
        cleaned, stats = engine.filter(text, findings)
        # cleaned is the filtered list; stats shows how many were suppressed
    """

    def __init__(
        self,
        enabled: bool = True,
        hard_suppress_threshold: float = FP_HARD_SUPPRESS_THRESHOLD,
        soft_suppress_threshold: float = FP_SOFT_SUPPRESS_THRESHOLD,
        suppress_info_and_low: bool = True,
    ):
        """
        Args:
            enabled: Whether FP engine is active. Set to False to pass through.
            hard_suppress_threshold: FP score required to suppress CRITICAL findings.
            soft_suppress_threshold: FP score to downgrade HIGH→MEDIUM findings.
            suppress_info_and_low: Whether to suppress INFO/LOW findings when FP signals found.
        """
        self._enabled = enabled
        self._hard_thresh = hard_suppress_threshold
        self._soft_thresh = soft_suppress_threshold
        self._suppress_info_low = suppress_info_and_low

    @property
    def patterns(self) -> dict[str, Any]:
        return _load_fp_patterns()

    def filter(
        self,
        text: str,
        findings: list[Finding],
    ) -> tuple[list[Finding], FPEngineStats]:
        """
        Apply FP reduction to a list of findings for the given text.

        Args:
            text: The original input text that was scanned.
            findings: Raw findings from scanners.

        Returns:
            (filtered_findings, stats) — filtered list and stats object.
        """
        if not self._enabled or not findings:
            stats = FPEngineStats(total_findings=len(findings), passed_unchanged=len(findings))
            return findings, stats

        stats = FPEngineStats(total_findings=len(findings))
        results: list[Finding] = []

        # Pre-compute global FP signals for this text (shared across all findings)
        global_fp_score, global_signals = self._compute_global_fp_score(text)

        for finding in findings:
            fp_result = self._evaluate_finding(text, finding, global_fp_score, global_signals)
            stats.total_findings  # already counted
            if fp_result.suppressed:
                stats.suppressed += 1
                logger.debug(
                    "FP suppressed: rule=%s fp_score=%.2f signals=%s",
                    finding.rule_id, fp_result.fp_score, fp_result.matched_signals,
                )
            elif fp_result.downgraded_severity is not None:
                stats.downgraded += 1
                results.append(fp_result.final_finding)  # type: ignore[arg-type]
                logger.debug(
                    "FP downgraded: rule=%s %s→%s fp_score=%.2f",
                    finding.rule_id,
                    finding.severity.name,
                    fp_result.downgraded_severity.name,
                    fp_result.fp_score,
                )
            else:
                stats.passed_unchanged += 1
                results.append(finding)

        return results, stats

    # ─── Internal helpers ─────────────────────────────────────────────────

    def _compute_global_fp_score(self, text: str) -> tuple[float, list[str]]:
        """Compute global FP score from text-level signals."""
        patterns = self.patterns
        if not patterns:
            return 0.0, []

        text_lower = text.lower()
        total_penalty = 0.0
        signals: list[str] = []

        # Check known-safe payloads first
        if text.strip().lower() in patterns.get("_safe_set", frozenset()):
            return 1.0, ["known_safe_payload"]

        # Check safe context indicators
        for indicator in patterns.get("safe_context_indicators", []):
            phrase = indicator["phrase"].lower()
            if phrase in text_lower:
                penalty = float(indicator.get("confidence_penalty", 0.10))
                total_penalty += penalty
                signals.append(f"context:{phrase[:30]}")

        # Domain allowlist context signals
        for _domain, domain_cfg in patterns.get("domain_allowlists", {}).items():
            for signal in domain_cfg.get("context_signals", []):
                try:
                    if re.search(signal, text, re.IGNORECASE):
                        total_penalty += 0.10
                        signals.append(f"domain:{signal[:20]}")
                except re.error:
                    if signal.lower() in text_lower:
                        total_penalty += 0.10
                        signals.append(f"domain:{signal[:20]}")

        # Cap at 0.9 — never reach "definite benign" from context signals alone
        fp_score = min(total_penalty, 0.90)
        return fp_score, signals

    def _evaluate_finding(
        self,
        text: str,
        finding: Finding,
        global_fp_score: float,
        global_signals: list[str],
    ) -> FPResult:
        """Evaluate one finding and determine whether to suppress/downgrade."""
        patterns = self.patterns
        fp_score = global_fp_score
        signals = list(global_signals)
        rule_name = self._extract_rule_name(finding)

        # Check benign patterns
        for bp in patterns.get("benign_patterns", []):
            applies_to = bp.get("applies_to_rules", [])
            if applies_to and rule_name and rule_name not in applies_to:
                continue
            compiled: re.Pattern = bp["_compiled"]
            if compiled.search(text):
                penalty = float(bp.get("confidence_penalty", 0.10))
                fp_score = min(fp_score + penalty, 0.99)
                signals.append(f"benign:{bp['id']}")

        # Check suppressors
        for sup in patterns.get("fp_suppressors", []):
            triggered_by = sup.get("triggered_by_rules", [])
            if triggered_by and rule_name and rule_name not in triggered_by:
                continue
            compiled: re.Pattern = sup["_compiled"]
            if compiled.search(text):
                action_str = sup.get("action", "penalize")
                action = FPAction(action_str) if action_str in FPAction._value2member_map_ else FPAction.PENALIZE
                signals.append(f"suppressor:{sup['id']}")
                # Apply the suppressor action
                return self._apply_suppressor_action(finding, fp_score, action, signals)

        # Apply threshold-based decisions
        return self._apply_threshold_decision(finding, fp_score, signals)

    def _apply_suppressor_action(
        self,
        finding: Finding,
        fp_score: float,
        action: FPAction,
        signals: list[str],
    ) -> FPResult:
        """Apply a matched suppressor action to a finding."""
        sev = finding.severity

        if action == FPAction.SUPPRESS:
            # Only suppress non-CRITICAL unless we have high confidence
            if sev == Severity.CRITICAL and fp_score < self._hard_thresh:
                # Downgrade to HIGH instead of suppressing
                new_finding = self._clone_with_severity(finding, Severity.HIGH)
                return FPResult(
                    original_finding=finding,
                    fp_score=fp_score,
                    action=FPAction.DOWNGRADE_TO_MEDIUM,
                    suppressed=False,
                    downgraded_severity=Severity.HIGH,
                    matched_signals=signals,
                    final_finding=new_finding,
                )
            return FPResult(
                original_finding=finding,
                fp_score=fp_score,
                action=FPAction.SUPPRESS,
                suppressed=True,
                downgraded_severity=None,
                matched_signals=signals,
                final_finding=None,
            )

        elif action == FPAction.DOWNGRADE_TO_INFO:
            new_finding = self._clone_with_severity(finding, Severity.INFO)
            return FPResult(
                original_finding=finding,
                fp_score=fp_score,
                action=action,
                suppressed=False,
                downgraded_severity=Severity.INFO,
                matched_signals=signals,
                final_finding=new_finding,
            )

        elif action == FPAction.DOWNGRADE_TO_LOW:
            new_finding = self._clone_with_severity(finding, Severity.LOW)
            return FPResult(
                original_finding=finding,
                fp_score=fp_score,
                action=action,
                suppressed=False,
                downgraded_severity=Severity.LOW,
                matched_signals=signals,
                final_finding=new_finding,
            )

        elif action == FPAction.DOWNGRADE_TO_MEDIUM:
            new_finding = self._clone_with_severity(finding, Severity.MEDIUM)
            return FPResult(
                original_finding=finding,
                fp_score=fp_score,
                action=action,
                suppressed=False,
                downgraded_severity=Severity.MEDIUM,
                matched_signals=signals,
                final_finding=new_finding,
            )

        # Default: penalize only
        return self._apply_threshold_decision(finding, fp_score, signals)

    def _apply_threshold_decision(
        self,
        finding: Finding,
        fp_score: float,
        signals: list[str],
    ) -> FPResult:
        """Apply threshold-based decision using fp_score."""
        sev = finding.severity

        # INFO/LOW: suppress if any FP signal found and enabled
        if self._suppress_info_low and sev in (Severity.INFO, Severity.LOW):
            if fp_score >= self._soft_thresh:
                return FPResult(
                    original_finding=finding,
                    fp_score=fp_score,
                    action=FPAction.SUPPRESS,
                    suppressed=True,
                    downgraded_severity=None,
                    matched_signals=signals,
                    final_finding=None,
                )

        # HIGH: downgrade to MEDIUM above soft threshold
        if sev == Severity.HIGH and fp_score >= self._soft_thresh:
            new_finding = self._clone_with_severity(finding, Severity.MEDIUM)
            return FPResult(
                original_finding=finding,
                fp_score=fp_score,
                action=FPAction.DOWNGRADE_TO_MEDIUM,
                suppressed=False,
                downgraded_severity=Severity.MEDIUM,
                matched_signals=signals,
                final_finding=new_finding,
            )

        # CRITICAL: only suppress above hard threshold
        if sev == Severity.CRITICAL and fp_score >= self._hard_thresh:
            new_finding = self._clone_with_severity(finding, Severity.HIGH)
            return FPResult(
                original_finding=finding,
                fp_score=fp_score,
                action=FPAction.DOWNGRADE_TO_MEDIUM,
                suppressed=False,
                downgraded_severity=Severity.HIGH,
                matched_signals=signals,
                final_finding=new_finding,
            )

        # Pass through unchanged
        return FPResult(
            original_finding=finding,
            fp_score=fp_score,
            action=None,
            suppressed=False,
            downgraded_severity=None,
            matched_signals=signals,
            final_finding=finding,
        )

    @staticmethod
    def _extract_rule_name(finding: Finding) -> str:
        """Extract the rule name from finding metadata for pattern matching."""
        # Try metadata first, then rule_id, then name
        meta = getattr(finding, "metadata", None) or {}
        if isinstance(meta, dict):
            name = meta.get("rule_name") or meta.get("name") or ""
            if name:
                return str(name)
        rule_id = getattr(finding, "rule_id", "") or ""
        return str(rule_id).lower()

    @staticmethod
    def _clone_with_severity(finding: Finding, new_severity: Severity) -> Finding:
        """Create a copy of a Finding with a different severity."""
        try:
            # Finding is a dataclass — use replace-style construction
            import dataclasses
            if dataclasses.is_dataclass(finding):
                return dataclasses.replace(finding, severity=new_severity)
        except (TypeError, AttributeError):
            pass
        # Fallback: construct new Finding with same fields
        kwargs = {}
        for attr in ("rule_id", "title", "description", "confidence", "metadata",
                     "domain", "finding_type", "matched_text", "source"):
            val = getattr(finding, attr, None)
            if val is not None:
                kwargs[attr] = val
        kwargs["severity"] = new_severity
        try:
            return Finding(**kwargs)
        except TypeError:
            # If Finding doesn't accept all those kwargs, return original
            return finding
