"""
Embedding stability detector — checks stability across model versions.

Compares embeddings from two model versions for the same inputs.
Large drift may indicate backdoor insertion, fine-tuning attacks,
or unintended degradation.
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass

from sentinel.finding import Finding, Severity

_log = logging.getLogger("sentinel.supply_chain.stability_detector")


@dataclass
class StabilityResult:
    mean_drift: float
    max_drift: float
    drifted_count: int
    total_count: int
    drift_ratio: float


class StabilityDetector:
    """Detect embedding drift between model versions."""

    def __init__(self, drift_threshold: float = 0.5, ratio_threshold: float = 0.1):
        self._drift_threshold = drift_threshold
        self._ratio_threshold = ratio_threshold

    def compare(
        self,
        embeddings_v1: list[list[float]],
        embeddings_v2: list[list[float]],
        source: str = "",
    ) -> tuple[StabilityResult, list[Finding]]:
        """Compare embeddings from two versions.

        Args:
            embeddings_v1: Embeddings from version 1.
            embeddings_v2: Embeddings from version 2 (same inputs).
            source: Source identifier.

        Returns:
            (StabilityResult, list of findings)
        """
        findings: list[Finding] = []

        if len(embeddings_v1) != len(embeddings_v2):
            findings.append(Finding.artifact(
                rule_id="STABILITY-001",
                title="Embedding count mismatch between versions",
                description=f"v1 has {len(embeddings_v1)}, v2 has {len(embeddings_v2)}",
                severity=Severity.MEDIUM,
                target=source,
            ))
            min_len = min(len(embeddings_v1), len(embeddings_v2))
            embeddings_v1 = embeddings_v1[:min_len]
            embeddings_v2 = embeddings_v2[:min_len]

        if not embeddings_v1:
            return StabilityResult(0, 0, 0, 0, 0), findings

        drifts = [
            self._cosine_distance(e1, e2)
            for e1, e2 in zip(embeddings_v1, embeddings_v2)
        ]
        drifted = sum(1 for d in drifts if d > self._drift_threshold)
        total = len(drifts)
        mean_drift = sum(drifts) / total
        max_drift = max(drifts)
        ratio = drifted / total

        result = StabilityResult(
            mean_drift=mean_drift,
            max_drift=max_drift,
            drifted_count=drifted,
            total_count=total,
            drift_ratio=ratio,
        )

        if ratio > self._ratio_threshold:
            findings.append(Finding.artifact(
                rule_id="STABILITY-002",
                title="Significant embedding drift between versions",
                description=(
                    f"{drifted}/{total} embeddings ({ratio:.1%}) drifted beyond threshold "
                    f"{self._drift_threshold}. Mean drift: {mean_drift:.4f}, max: {max_drift:.4f}."
                ),
                severity=Severity.HIGH,
                target=source,
                evidence=f"drift_ratio={ratio:.3f}, mean={mean_drift:.4f}",
            ))

        if max_drift > 1.5:
            findings.append(Finding.artifact(
                rule_id="STABILITY-003",
                title="Extreme embedding drift detected",
                description=f"Maximum drift {max_drift:.4f} suggests potential backdoor or model replacement.",
                severity=Severity.CRITICAL,
                target=source,
                evidence=f"max_drift={max_drift:.4f}",
            ))

        return result, findings

    @staticmethod
    def _cosine_distance(a: list[float], b: list[float]) -> float:
        dot = sum(x * y for x, y in zip(a, b))
        norm_a = math.sqrt(sum(x * x for x in a))
        norm_b = math.sqrt(sum(x * x for x in b))
        if norm_a == 0 or norm_b == 0:
            return 1.0
        similarity = dot / (norm_a * norm_b)
        return 1.0 - max(-1.0, min(1.0, similarity))
