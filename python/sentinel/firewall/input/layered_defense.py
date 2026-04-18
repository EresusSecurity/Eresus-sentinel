"""
Eresus Sentinel — Layered Defense Orchestrator

Combines 4 detection layers into a unified defense pipeline:
    Layer 1: Heuristic keyword matching (fast, always available)
    Layer 2: ML classifier (optional, requires transformers)
    Layer 3: Canary token injection/detection (active defense)
    Layer 4: Vector similarity search (corpus-based, zero-dep)

Pipeline logic:
    - Fast path: Layer 1 high-confidence → immediate block
    - Full path: All layers vote → weighted confidence aggregation
    - Short-circuit: BLOCK from any layer with score > 0.9 → immediate

The orchestrator does NOT replace FirewallPipeline — it sits
alongside it as a specialized injection defense component.
"""

from __future__ import annotations

import logging
from typing import Optional

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import InputScanner, ScanResult, ScanAction

logger = logging.getLogger(__name__)


class LayerWeight:
    """Configuration for a single defense layer."""

    __slots__ = ("name", "weight", "enabled", "short_circuit_threshold")

    def __init__(
        self,
        name: str,
        weight: float = 1.0,
        enabled: bool = True,
        short_circuit_threshold: float = 0.9,
    ):
        self.name = name
        self.weight = weight
        self.enabled = enabled
        self.short_circuit_threshold = short_circuit_threshold


DEFAULT_WEIGHTS = {
    "heuristic": LayerWeight("heuristic", weight=0.25, short_circuit_threshold=0.85),
    "ml_classifier": LayerWeight("ml_classifier", weight=0.35, short_circuit_threshold=0.95),
    "canary": LayerWeight("canary", weight=0.20, short_circuit_threshold=1.0),
    "vector": LayerWeight("vector", weight=0.20, short_circuit_threshold=0.9),
}


class LayeredDefense(InputScanner):
    """
    Multi-layer injection defense orchestrator.

    Runs up to 4 detection layers and aggregates results
    using configurable weighted voting:

        final_score = Σ(layer_score × layer_weight) / Σ(active_weights)

    Short-circuit: if any layer returns score > its threshold,
    immediately block without running remaining layers.

    Usage:
        from sentinel.firewall.input.layered_defense import LayeredDefense
        from sentinel.firewall.input.heuristic import HeuristicInjectionScanner
        from sentinel.firewall.input.ml_classifier import MLClassifier
        from sentinel.firewall.input.vector_scanner import VectorScanner
        from sentinel.firewall.input.canary import CanaryInjector

        defense = LayeredDefense(
            heuristic=HeuristicInjectionScanner(),
            ml_classifier=MLClassifier(),
            vector=VectorScanner(),
            canary=CanaryInjector(),
        )
        result = defense.scan("ignore previous instructions")
    """

    def __init__(
        self,
        heuristic: Optional[InputScanner] = None,
        ml_classifier: Optional[InputScanner] = None,
        vector: Optional[InputScanner] = None,
        canary=None,
        block_threshold: float = 0.65,
        warn_threshold: float = 0.40,
        layer_weights: Optional[dict[str, LayerWeight]] = None,
    ):
        """
        Args:
            heuristic: Layer 1 — HeuristicInjectionScanner instance.
            ml_classifier: Layer 2 — MLClassifier instance.
            vector: Layer 4 — VectorScanner instance.
            canary: Layer 3 — CanaryInjector instance (used for inject/detect).
            block_threshold: Aggregated score above this → BLOCK.
            warn_threshold: Aggregated score above this → WARN.
            layer_weights: Custom layer weight configuration.
        """
        self._heuristic = heuristic
        self._ml_classifier = ml_classifier
        self._vector = vector
        self._canary = canary
        self._block_threshold = block_threshold
        self._warn_threshold = warn_threshold
        self._weights = layer_weights or dict(DEFAULT_WEIGHTS)

    def scan(self, prompt: str) -> ScanResult:
        """
        Run all active layers and aggregate results.

        Returns aggregated ScanResult with all findings from all layers.
        """
        if not prompt or len(prompt.strip()) < 3:
            return ScanResult(
                sanitized=prompt,
                action=ScanAction.PASS,
                risk_score=0.0,
            )

        all_findings: list[Finding] = []
        layer_scores: list[tuple[str, float]] = []

        # ─── Layer 1: Heuristic ────────────────────────────────
        if self._heuristic and self._weights.get("heuristic", LayerWeight("h")).enabled:
            heuristic_result = self._heuristic.scan(prompt)
            all_findings.extend(heuristic_result.findings)
            layer_scores.append(("heuristic", heuristic_result.risk_score))

            # Short-circuit on high-confidence heuristic match
            sc_thresh = self._weights.get("heuristic", LayerWeight("h")).short_circuit_threshold
            if heuristic_result.risk_score >= sc_thresh:
                logger.info(
                    "LayeredDefense: heuristic short-circuit (score=%.3f)",
                    heuristic_result.risk_score,
                )
                return self._build_result(
                    prompt, 1.0, ScanAction.BLOCK,
                    all_findings, layer_scores, short_circuited="heuristic",
                )

        # ─── Layer 2: ML Classifier ───────────────────────────
        if self._ml_classifier and self._weights.get("ml_classifier", LayerWeight("m")).enabled:
            ml_result = self._ml_classifier.scan(prompt)
            all_findings.extend(ml_result.findings)
            layer_scores.append(("ml_classifier", ml_result.risk_score))

            sc_thresh = self._weights.get("ml_classifier", LayerWeight("m")).short_circuit_threshold
            if ml_result.risk_score >= sc_thresh:
                logger.info(
                    "LayeredDefense: ML short-circuit (score=%.3f)",
                    ml_result.risk_score,
                )
                return self._build_result(
                    prompt, 1.0, ScanAction.BLOCK,
                    all_findings, layer_scores, short_circuited="ml_classifier",
                )

        # ─── Layer 3: Canary (detect only — inject is external) ─
        # Canary detection happens at the output stage, not input.
        # We include the canary weight in aggregation only if
        # a canary result was explicitly passed in.

        # ─── Layer 4: Vector Similarity ────────────────────────
        if self._vector and self._weights.get("vector", LayerWeight("v")).enabled:
            vector_result = self._vector.scan(prompt)
            all_findings.extend(vector_result.findings)
            layer_scores.append(("vector", vector_result.risk_score))

            sc_thresh = self._weights.get("vector", LayerWeight("v")).short_circuit_threshold
            if vector_result.risk_score >= sc_thresh:
                logger.info(
                    "LayeredDefense: vector short-circuit (score=%.3f)",
                    vector_result.risk_score,
                )
                return self._build_result(
                    prompt, 1.0, ScanAction.BLOCK,
                    all_findings, layer_scores, short_circuited="vector",
                )

        # ─── Aggregation ──────────────────────────────────────
        if not layer_scores:
            return ScanResult(
                sanitized=prompt,
                action=ScanAction.PASS,
                risk_score=0.0,
            )

        final_score = self._aggregate_scores(layer_scores)

        if final_score >= self._block_threshold:
            action = ScanAction.BLOCK
        elif final_score >= self._warn_threshold:
            action = ScanAction.WARN
        else:
            action = ScanAction.PASS

        return self._build_result(
            prompt, final_score, action, all_findings, layer_scores,
        )

    def _aggregate_scores(
        self,
        layer_scores: list[tuple[str, float]],
    ) -> float:
        """
        Weighted average of layer scores.

        Only active layers with non-zero weight contribute.
        """
        total_weight = 0.0
        weighted_sum = 0.0

        for layer_name, score in layer_scores:
            weight_config = self._weights.get(
                layer_name, LayerWeight(layer_name, weight=1.0)
            )
            weighted_sum += score * weight_config.weight
            total_weight += weight_config.weight

        if total_weight == 0:
            return 0.0

        return weighted_sum / total_weight

    def _build_result(
        self,
        prompt: str,
        score: float,
        action: ScanAction,
        findings: list[Finding],
        layer_scores: list[tuple[str, float]],
        short_circuited: Optional[str] = None,
    ) -> ScanResult:
        """Build a ScanResult with a layered defense summary finding."""
        # Add a summary finding for the layered defense itself
        layer_summary = ", ".join(
            f"{name}={s:.3f}" for name, s in layer_scores
        )

        severity = Severity.CRITICAL if score > 0.9 else (
            Severity.HIGH if score > 0.65 else (
                Severity.MEDIUM if score > 0.4 else Severity.LOW
            )
        )

        summary_desc = (
            f"Layered defense aggregated score: {score:.3f}. "
            f"Layer breakdown: {layer_summary}."
        )
        if short_circuited:
            summary_desc += (
                f" Short-circuited by {short_circuited} layer."
            )

        if action in (ScanAction.BLOCK, ScanAction.WARN):
            summary_finding = Finding.firewall_input(
                rule_id="FIREWALL-INPUT-040",
                title="Layered defense: injection detected",
                description=summary_desc,
                severity=severity,
                confidence=score,
                target="<prompt>",
                evidence=layer_summary,
                cwe_ids=["CWE-77"],
                tags=["owasp:llm01", "layer:aggregated"],
                remediation=(
                    "Multiple defense layers flagged this prompt. "
                    "Review for injection patterns."
                ),
            )
            findings.append(summary_finding)

        return ScanResult(
            sanitized=prompt,
            action=action,
            risk_score=score,
            findings=findings,
        )

    def scan_with_canary(
        self,
        prompt: str,
        response: str,
        canary: str,
    ) -> ScanResult:
        """
        Full pipeline: scan input + check canary leakage in output.

        This provides the complete 4-layer defense:
        1. Scan input (heuristic + ML + vector)
        2. Check output for canary leakage (canary layer)

        Args:
            prompt: User's input prompt
            response: LLM's response (after inference)
            canary: The canary word embedded in system prompt

        Returns:
            Aggregated ScanResult from all 4 layers.
        """
        # Run input layers
        input_result = self.scan(prompt)

        # Run canary detection on output
        if self._canary and self._weights.get("canary", LayerWeight("c")).enabled:
            canary_result = self._canary.detect(response, canary)

            # Merge canary findings
            all_findings = list(input_result.findings) + canary_result.findings

            # Re-aggregate with canary score
            input_scores = [
                (name, score) for name, score in [
                    ("input_layers", input_result.risk_score),
                    ("canary", canary_result.risk_score),
                ]
            ]

            final_score = max(input_result.risk_score, canary_result.risk_score)

            if final_score >= self._block_threshold:
                action = ScanAction.BLOCK
            elif final_score >= self._warn_threshold:
                action = ScanAction.WARN
            else:
                action = ScanAction.PASS

            return ScanResult(
                sanitized=prompt,
                action=action,
                risk_score=final_score,
                findings=all_findings,
            )

        return input_result

    def get_layer_status(self) -> dict:
        """Return status of each layer."""
        status = {}

        status["heuristic"] = {
            "available": self._heuristic is not None,
            "enabled": self._weights.get("heuristic", LayerWeight("h")).enabled,
            "weight": self._weights.get("heuristic", LayerWeight("h")).weight,
        }

        ml_available = False
        if self._ml_classifier:
            ml_available = getattr(self._ml_classifier, "is_available", False)
        status["ml_classifier"] = {
            "available": ml_available,
            "enabled": self._weights.get("ml_classifier", LayerWeight("m")).enabled,
            "weight": self._weights.get("ml_classifier", LayerWeight("m")).weight,
        }

        status["canary"] = {
            "available": self._canary is not None,
            "enabled": self._weights.get("canary", LayerWeight("c")).enabled,
            "weight": self._weights.get("canary", LayerWeight("c")).weight,
        }

        status["vector"] = {
            "available": self._vector is not None,
            "enabled": self._weights.get("vector", LayerWeight("v")).enabled,
            "weight": self._weights.get("vector", LayerWeight("v")).weight,
        }

        return status
