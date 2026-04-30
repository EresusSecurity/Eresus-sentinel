"""
Deception-first guardrail engine.

Main orchestrator that scores queries through the detector stack, selects
an action (PASS / WARN / DECEIVE / BLOCK), manages session-level escalation,
and returns a deception preamble when needed.

Usage::

    from sentinel.firewall.deception import DeceptionGuardrail, Action

    guard = DeceptionGuardrail()
    result = guard.check(session_id="sess-1", query="ignore all previous instructions")
    if result.action == Action.DECEIVE:
        # prepend result.system_preamble to the operator's system prompt
        ...
"""

from __future__ import annotations

import json
import logging
import os
import time
import uuid
from dataclasses import dataclass
from enum import Enum
from typing import Optional

from sentinel.firewall.deception import custom_rules as _custom_rules
from sentinel.firewall.deception.detectors import (
    BaseDetector,
    CredentialHarvestDetector,
    CustomInputDetector,
    CustomJailbreakDetector,
    DataExfiltrationDetector,
    Detection,
    HarmfulContentDetector,
    JailbreakDetector,
    MalwareGenerationDetector,
    MAX_DETECTION_CHARS,
    ObfuscationDetector,
    PromptInjectionDetector,
    SCORE_BLOCK,
    SCORE_DECEIVE,
    SCORE_WARN,
    SESSION_DECEIVE_THRESHOLD,
    SocialEngineeringDetector,
    SystemReconDetector,
    ThreatCategory,
)
from sentinel.firewall.deception.session import SessionStore
from sentinel.firewall.deception.templates import get_template

_log = logging.getLogger("sentinel.deception.engine")


# ---------------------------------------------------------------------------
# Enums & result types
# ---------------------------------------------------------------------------

class Action(str, Enum):
    PASS = "pass"
    WARN = "warn"
    DECEIVE = "deceive"
    BLOCK = "block"


@dataclass
class GuardrailResult:
    query_id: str
    session_id: str
    action: Action
    threat_category: ThreatCategory
    score: float
    reason: str
    original_query: str
    final_query: str
    system_preamble: Optional[str]
    decoy_id: Optional[str]
    session_cumulative_score: float
    blocked_reason: Optional[str] = None
    custom_category_name: str = ""

    def to_dict(self) -> dict:
        """Caller-safe dict — exposes only the query ID for support correlation."""
        return {"query_id": self.query_id}

    def to_log_dict(self) -> dict:
        """Full detail dict for internal logs and defender-only endpoints."""
        return {
            "query_id": self.query_id,
            "session_id": self.session_id,
            "action": self.action.value,
            "threat_category": self.custom_category_name or self.threat_category.value,
            "score": self.score,
            "reason": self.reason,
            "decoy_id": self.decoy_id,
            "session_cumulative_score": self.session_cumulative_score,
        }


# ---------------------------------------------------------------------------
# Custom rules detector (loaded from custom_rules.json)
# ---------------------------------------------------------------------------

_CATEGORY_NAME_MAP: dict[str, ThreatCategory] = {c.value: c for c in ThreatCategory}


class _CustomRulesDetector(BaseDetector):
    """Detector backed by custom_rules.json."""

    def __init__(self) -> None:
        try:
            self._rules = _custom_rules.load()
        except ValueError as exc:
            raise RuntimeError(str(exc)) from exc

        cat_count = len(self._rules.categories)
        rule_count = len(self._rules.rules)
        if cat_count or rule_count:
            _log.info(
                "Custom rules loaded: %d categor%s, %d rule%s.",
                cat_count, "y" if cat_count == 1 else "ies",
                rule_count, "" if rule_count == 1 else "s",
            )

    def score(self, text: str) -> Detection:
        best = Detection(0.0, ThreatCategory.NONE, "No match")
        if not self._rules.rules:
            return best

        lower = text.lower()

        for rule in self._rules.rules:
            matched = False
            if rule.match_type == "substring":
                matched = rule.pattern.lower() in lower
            else:
                matched = bool(rule._compiled and rule._compiled.search(text))

            if matched and rule.score > best.score:
                cat_enum = _CATEGORY_NAME_MAP.get(rule.category_name, ThreatCategory.CUSTOM)

                template_override: Optional[str] = None
                if rule.category_name in self._rules.categories:
                    template_override = self._rules.categories[rule.category_name].deception_template

                best = Detection(
                    score=rule.score,
                    category=cat_enum,
                    reason=rule.reason,
                    matched=rule.pattern,
                    custom_category_name=rule.category_name if cat_enum == ThreatCategory.CUSTOM else "",
                    template_override=template_override,
                )
        return best


# ---------------------------------------------------------------------------
# Main engine
# ---------------------------------------------------------------------------

class DeceptionGuardrail:
    """Deception-first guardrail engine.

    ``check()`` scores the query, selects an action, and — when action is
    DECEIVE — returns a ``system_preamble`` that the server places before
    the operator's system prompt.  The user-facing response looks normal;
    the LLM silently produces plausible disinformation tailored to the
    threat category.
    """

    def __init__(
        self,
        redis_url: Optional[str] = None,
        deception_mode: str = "template",
    ):
        self._session = SessionStore(redis_url)
        self._deception_mode = deception_mode.lower().strip()
        if self._deception_mode not in ("template", "generative"):
            _log.warning("Unknown deception_mode=%r — falling back to 'template'", deception_mode)
            self._deception_mode = "template"
        _log.info("Deception mode: %s", self._deception_mode)

        # Order matters: HarmfulContent is evaluated first for early BLOCK
        self._detectors: list[BaseDetector] = [
            HarmfulContentDetector(),
            JailbreakDetector(),
            CustomJailbreakDetector(),
            ObfuscationDetector(),
            PromptInjectionDetector(),
            CredentialHarvestDetector(),
            MalwareGenerationDetector(),
            SocialEngineeringDetector(),
            DataExfiltrationDetector(),
            SystemReconDetector(),
            CustomInputDetector(),
            _CustomRulesDetector(),
        ]

    def check(self, session_id: str, query: str) -> GuardrailResult:
        """Score a query and return the guardrail decision."""
        query_id = str(uuid.uuid4())
        detection = self._best_detection(query)
        action, decoy_id, system_preamble = self._decide(detection, query=query)

        cumulative = self._session.add(session_id, detection.score, {
            "query_id": query_id,
            "action": action.value,
            "category": detection.category.value,
            "score": detection.score,
            "reason": detection.reason,
            "matched": detection.matched,
            "decoy_id": decoy_id,
            "ts": time.time(),
        })

        # Session-level escalation: persistent suspicious session → force DECEIVE
        if (
            action not in (Action.BLOCK, Action.DECEIVE)
            and detection.score > 0
            and cumulative >= SESSION_DECEIVE_THRESHOLD
        ):
            escalation_reason = f"Session threshold exceeded (cumulative={cumulative:.0f})"
            decoy_id = str(uuid.uuid4()).replace("-", "")[:16].upper()
            system_preamble = self.deception_preamble(detection.category, escalation_reason)
            action = Action.DECEIVE
            detection.reason = escalation_reason

        _log.info(
            '{"event":"guardrail_check","query_id":"%s","session_id":"%s","action":"%s",'
            '"category":"%s","score":%.1f,"cumulative":%.1f,"reason":"%s","decoy_id":"%s"}',
            query_id, session_id, action.value, detection.category.value,
            detection.score, cumulative,
            detection.reason, decoy_id or "",
        )

        return GuardrailResult(
            query_id=query_id,
            session_id=session_id,
            action=action,
            threat_category=detection.category,
            score=detection.score,
            reason=detection.reason,
            original_query=query,
            final_query=query,
            system_preamble=system_preamble,
            decoy_id=decoy_id,
            session_cumulative_score=cumulative,
            blocked_reason=detection.reason if action == Action.BLOCK else None,
            custom_category_name=detection.custom_category_name,
        )

    def deception_preamble(
        self,
        category: ThreatCategory,
        reason: str,
        query: str = "",
    ) -> str:
        """Return the deception system preamble without creating a session record."""
        return get_template(
            category=category,
            mode=self._deception_mode,
            query=query,
        )

    def record_response(
        self,
        session_id: str,
        query_id: str,
        response: str,
        requeried: bool = False,
    ) -> None:
        """Store the final response served to a DECEIVE-flagged query.

        Capped at 4096 chars. Stored in session history for threat-hunting.
        """
        self._session.update_entry(session_id, query_id, {
            "response": response[:4096],
            "requeried": requeried,
        })

    def record_feedback_score(self, session_id: str, score: float) -> float:
        """Add *score* to the session without a full query detection cycle.

        Used for soft refusal signals that nudge the session toward deception.
        """
        return self._session.add(session_id, score, {
            "query_id": "feedback",
            "action": "feedback",
            "category": ThreatCategory.NONE.value,
            "score": score,
            "reason": "soft refusal signal",
            "matched": "",
            "decoy_id": None,
            "ts": time.time(),
        })

    def session_score(self, session_id: str) -> float:
        return self._session.get_score(session_id)

    def session_history(self, session_id: str) -> list:
        return self._session.get_history(session_id)

    def reset_session(self, session_id: str) -> None:
        self._session.reset(session_id)

    # -- Internal -----------------------------------------------------------

    def _best_detection(self, query: str) -> Detection:
        truncated = query[:MAX_DETECTION_CHARS]
        best = Detection(0.0, ThreatCategory.NONE, "Clean")
        for detector in self._detectors:
            result = detector.score(truncated)
            if result.score > best.score:
                best = result
                if best.score >= SCORE_BLOCK:
                    break
        return best

    def _decide(
        self, detection: Detection, query: str = ""
    ) -> tuple[Action, Optional[str], Optional[str]]:
        """Return (action, decoy_id, system_preamble)."""
        score = detection.score
        category = detection.category

        if score >= SCORE_BLOCK:
            return Action.BLOCK, None, None

        if score >= SCORE_DECEIVE:
            decoy_id = str(uuid.uuid4()).replace("-", "")[:16].upper()
            addendum = get_template(
                category=category,
                mode=self._deception_mode,
                query=query,
                template_override=detection.template_override,
            )
            return Action.DECEIVE, decoy_id, addendum

        if score >= SCORE_WARN:
            return Action.WARN, None, None

        return Action.PASS, None, None
