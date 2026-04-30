"""
Deduplication detector — finds duplicate/near-duplicate embeddings.

High duplicate ratios in embedding datasets can indicate:
  - Data poisoning (repeated adversarial examples)
  - Training data contamination
  - Index corruption
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass

from sentinel.finding import Finding, Severity

_log = logging.getLogger("sentinel.supply_chain.dedup_detector")


@dataclass
class DedupResult:
    total: int
    exact_duplicates: int
    near_duplicates: int
    duplicate_ratio: float


class DedupDetector:
    """Detect duplicate and near-duplicate embeddings."""

    def __init__(self, similarity_threshold: float = 0.99, ratio_alert: float = 0.05):
        self._sim_threshold = similarity_threshold
        self._ratio_alert = ratio_alert

    def analyze(
        self,
        embeddings: list[list[float]],
        source: str = "",
    ) -> tuple[DedupResult, list[Finding]]:
        """Find duplicates in an embedding set.

        Uses pairwise cosine similarity (O(n²) — use sampling for large sets).
        """
        findings: list[Finding] = []
        n = len(embeddings)

        if n < 2:
            return DedupResult(n, 0, 0, 0.0), findings

        # Sample if too large
        sample = embeddings[:min(n, 5000)]
        sample_n = len(sample)

        exact = 0
        near = 0

        for i in range(sample_n):
            for j in range(i + 1, min(i + 100, sample_n)):  # Windowed comparison
                sim = self._cosine_sim(sample[i], sample[j])
                if sim >= 1.0 - 1e-8:
                    exact += 1
                elif sim >= self._sim_threshold:
                    near += 1

        total_pairs = sample_n * (sample_n - 1) // 2
        dup_ratio = (exact + near) / max(1, min(total_pairs, sample_n * 100))

        result = DedupResult(
            total=n,
            exact_duplicates=exact,
            near_duplicates=near,
            duplicate_ratio=dup_ratio,
        )

        if dup_ratio > self._ratio_alert:
            findings.append(Finding.artifact(
                rule_id="DEDUP-001",
                title="High duplicate ratio in embeddings",
                description=(
                    f"{exact} exact + {near} near-duplicates found "
                    f"(ratio={dup_ratio:.3f} > {self._ratio_alert}). "
                    "May indicate data poisoning or contamination."
                ),
                severity=Severity.HIGH,
                target=source,
                evidence=f"exact={exact}, near={near}, ratio={dup_ratio:.4f}",
            ))

        if exact > 50:
            findings.append(Finding.artifact(
                rule_id="DEDUP-002",
                title="Excessive exact duplicates in embeddings",
                description=f"{exact} exact duplicate pairs found. Investigate data source.",
                severity=Severity.MEDIUM,
                target=source,
                evidence=f"exact_duplicates={exact}",
            ))

        return result, findings

    @staticmethod
    def _cosine_sim(a: list[float], b: list[float]) -> float:
        dot = sum(x * y for x, y in zip(a, b))
        norm_a = math.sqrt(sum(x * x for x in a))
        norm_b = math.sqrt(sum(x * x for x in b))
        if norm_a == 0 or norm_b == 0:
            return 0.0
        return dot / (norm_a * norm_b)
