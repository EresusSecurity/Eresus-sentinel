"""
Eresus Sentinel — Deception-First Guardrail Engine.

Philosophy: rather than refusing suspicious queries, the deception engine
silently rewrites the LLM system prompt so the model returns realistic-but-false
output.  Legitimate queries are never modified.

Sub-modules:
    detectors   — Regex-based threat category detectors (jailbreak, credential harvest, etc.)
    templates   — Deception preamble templates per threat category
    session     — Session-level scoring with in-memory or Redis backend
    engine      — Main DeceptionGuardrail orchestrator
    custom_rules — JSON-driven custom detection rules
    output_checker — LLM output quality evaluator
    llm_examiner — Optional LLM-based additive query classifier
"""

from sentinel.firewall.deception.engine import (
    Action,
    DeceptionGuardrail,
    GuardrailResult,
    ThreatCategory,
)

__all__ = [
    "Action",
    "DeceptionGuardrail",
    "GuardrailResult",
    "ThreatCategory",
]
