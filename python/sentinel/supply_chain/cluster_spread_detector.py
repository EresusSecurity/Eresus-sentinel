"""
Cluster spread detector — identifies embedding clusters with abnormal spread.

Abnormally tight or wide clusters in embedding spaces can indicate:
  - Data poisoning (tight clusters of adversarial examples)
  - Distribution shift (wide clusters from out-of-distribution data)
  - Duplicate injection (zero-spread clusters)
"""

from __future__ import annotations

import logging
import math
from dataclasses import dataclass
from typing import Optional

from sentinel.finding import Finding, Severity

_log = logging.getLogger("sentinel.supply_chain.cluster_spread")


@dataclass
class ClusterStats:
    cluster_id: int
    centroid: list[float]
    size: int
    spread: float  # average distance from centroid
    min_dist: float
    max_dist: float


class ClusterSpreadDetector:
    """Detect embedding clusters with anomalous spread."""

    def __init__(
        self,
        tight_threshold: float = 0.01,
        wide_threshold: float = 5.0,
        min_cluster_size: int = 5,
    ):
        self._tight = tight_threshold
        self._wide = wide_threshold
        self._min_size = min_cluster_size

    def analyze(
        self,
        embeddings: list[list[float]],
        labels: list[int],
        source: str = "",
    ) -> list[Finding]:
        """Analyze cluster spreads and flag anomalies.

        Args:
            embeddings: List of embedding vectors.
            labels: Cluster label for each embedding.
            source: Source identifier for findings.
        """
        findings: list[Finding] = []
        clusters = self._compute_cluster_stats(embeddings, labels)

        for cs in clusters:
            if cs.size < self._min_size:
                continue

            if cs.spread < self._tight:
                findings.append(Finding.artifact(
                    rule_id="CLUSTER-001",
                    title=f"Abnormally tight cluster (id={cs.cluster_id})",
                    description=(
                        f"Cluster {cs.cluster_id} ({cs.size} points) has spread "
                        f"{cs.spread:.6f} < threshold {self._tight}. "
                        "May indicate duplicate injection or data poisoning."
                    ),
                    severity=Severity.HIGH,
                    target=source,
                    evidence=f"spread={cs.spread:.6f}, size={cs.size}",
                ))

            if cs.spread > self._wide:
                findings.append(Finding.artifact(
                    rule_id="CLUSTER-002",
                    title=f"Abnormally wide cluster (id={cs.cluster_id})",
                    description=(
                        f"Cluster {cs.cluster_id} ({cs.size} points) has spread "
                        f"{cs.spread:.4f} > threshold {self._wide}. "
                        "May indicate distribution shift or mixed data sources."
                    ),
                    severity=Severity.MEDIUM,
                    target=source,
                    evidence=f"spread={cs.spread:.4f}, size={cs.size}",
                ))

        return findings

    def _compute_cluster_stats(
        self,
        embeddings: list[list[float]],
        labels: list[int],
    ) -> list[ClusterStats]:
        clusters: dict[int, list[list[float]]] = {}
        for emb, label in zip(embeddings, labels):
            clusters.setdefault(label, []).append(emb)

        stats = []
        for cid, points in clusters.items():
            if len(points) < 2:
                continue
            dim = len(points[0])
            centroid = [sum(p[d] for p in points) / len(points) for d in range(dim)]
            dists = [self._l2_dist(p, centroid) for p in points]
            stats.append(ClusterStats(
                cluster_id=cid,
                centroid=centroid,
                size=len(points),
                spread=sum(dists) / len(dists),
                min_dist=min(dists),
                max_dist=max(dists),
            ))
        return stats

    @staticmethod
    def _l2_dist(a: list[float], b: list[float]) -> float:
        return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b)))
