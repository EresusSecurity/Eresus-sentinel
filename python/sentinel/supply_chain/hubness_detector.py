"""Adversarial hubness detector — detect poisoned embeddings in model repos.
Detects:
- Hubness anomalies (vectors that are nearest neighbors to too many others)
- Cluster spread anomalies
- Embedding stability violations
- Near-duplicate poisoning
"""

from __future__ import annotations

import math
from dataclasses import dataclass, field
from enum import Enum, auto


class AnomalyType(Enum):
    HUBNESS = auto()
    CONCEPT_HUBNESS = auto()
    MODALITY_HUBNESS = auto()
    CLUSTER_SPREAD = auto()
    STABILITY = auto()
    NEAR_DUPLICATE = auto()
    DIMENSIONAL_COLLAPSE = auto()
    OUTLIER = auto()


@dataclass
class EmbeddingVector:
    vector_id: str
    values: list[float]
    metadata: dict = field(default_factory=dict)
    label: str = ""


@dataclass
class HubnessFinding:
    anomaly_type: AnomalyType
    severity: str
    description: str
    vector_ids: list[str] = field(default_factory=list)
    score: float = 0.0
    threshold: float = 0.0
    details: dict = field(default_factory=dict)


def _cosine_similarity(a: list[float], b: list[float]) -> float:
    if len(a) != len(b):
        return 0.0
    dot = sum(x * y for x, y in zip(a, b, strict=True))
    na = math.sqrt(sum(x * x for x in a))
    nb = math.sqrt(sum(x * x for x in b))
    if na == 0 or nb == 0:
        return 0.0
    return dot / (na * nb)


def _euclidean_distance(a: list[float], b: list[float]) -> float:
    if len(a) != len(b):
        return float("inf")
    return math.sqrt(sum((x - y) ** 2 for x, y in zip(a, b, strict=True)))


def _mean_vector(vectors: list[list[float]]) -> list[float]:
    if not vectors:
        return []
    dim = len(vectors[0])
    result = [0.0] * dim
    for v in vectors:
        for i in range(dim):
            result[i] += v[i]
    n = len(vectors)
    return [x / n for x in result]


def _median(values: list[float]) -> float:
    if not values:
        return 0.0
    ordered = sorted(values)
    mid = len(ordered) // 2
    if len(ordered) % 2:
        return ordered[mid]
    return (ordered[mid - 1] + ordered[mid]) / 2.0


def _robust_z_scores(values: list[float]) -> list[float]:
    center = _median(values)
    deviations = [abs(value - center) for value in values]
    mad = _median(deviations)
    if mad <= 1e-9:
        positive_deviations = [value for value in deviations if value > 0]
        mad = _median(positive_deviations) if positive_deviations else 1.0
    return [0.6745 * (value - center) / max(mad, 1e-9) for value in values]


class HubnessDetector:

    def __init__(
        self,
        k: int = 10,
        hubness_threshold: float = 3.0,
        robust_z_threshold: float = 3.0,
    ):
        self._k = k
        self._threshold = hubness_threshold
        self._robust_z_threshold = robust_z_threshold

    def detect(self, vectors: list[EmbeddingVector]) -> list[HubnessFinding]:
        if len(vectors) < self._k + 1:
            return []

        neighbor_counts: dict[str, int] = {v.vector_id: 0 for v in vectors}

        for i, vi in enumerate(vectors):
            dists = []
            for j, vj in enumerate(vectors):
                if i == j:
                    continue
                d = _euclidean_distance(vi.values, vj.values)
                dists.append((d, vj.vector_id))
            dists.sort()
            for _, vid in dists[: self._k]:
                neighbor_counts[vid] += 1

        expected = self._k
        findings = []
        ordered_ids = list(neighbor_counts)
        counts = [float(neighbor_counts[vid]) for vid in ordered_ids]
        robust_z_by_id = dict(zip(ordered_ids, _robust_z_scores(counts), strict=True))

        for vid, count in neighbor_counts.items():
            ratio = count / max(expected, 1)
            robust_z = robust_z_by_id.get(vid, 0.0)
            if ratio > self._threshold or robust_z > self._robust_z_threshold:
                findings.append(HubnessFinding(
                    anomaly_type=AnomalyType.HUBNESS,
                    severity=(
                        "HIGH"
                        if ratio > self._threshold * 2
                        or robust_z > self._robust_z_threshold * 2
                        else "MEDIUM"
                    ),
                    description=(
                        f"Vector {vid} is hub: k-occurrence={count} "
                        f"(ratio={ratio:.2f}, robust_z={robust_z:.2f})"
                    ),
                    vector_ids=[vid],
                    score=max(ratio, robust_z),
                    threshold=self._threshold,
                    details={
                        "k_occurrence": count,
                        "expected": expected,
                        "ratio": ratio,
                        "robust_z": robust_z,
                        "robust_z_threshold": self._robust_z_threshold,
                    },
                ))
        return findings


def _partition_vectors(
    vectors: list[EmbeddingVector],
    metadata_field: str,
) -> dict[str, list[EmbeddingVector]]:
    groups: dict[str, list[EmbeddingVector]] = {}
    for vector in vectors:
        value = vector.metadata.get(metadata_field) or vector.label or "unknown"
        groups.setdefault(str(value), []).append(vector)
    return groups


class ConceptAwareHubnessDetector:
    """Detect hubs inside semantic concept buckets."""

    def __init__(
        self,
        k: int = 10,
        hubness_threshold: float = 2.5,
        robust_z_threshold: float = 2.5,
        min_group_size: int = 4,
    ):
        self._k = k
        self._threshold = hubness_threshold
        self._robust_z_threshold = robust_z_threshold
        self._min_group_size = min_group_size

    def detect(
        self,
        vectors: list[EmbeddingVector],
        metadata_field: str = "concept",
    ) -> list[HubnessFinding]:
        findings: list[HubnessFinding] = []
        for concept, members in _partition_vectors(vectors, metadata_field).items():
            if len(members) < self._min_group_size:
                continue
            effective_k = min(self._k, max(1, len(members) // 3))
            detector = HubnessDetector(
                k=effective_k,
                hubness_threshold=self._threshold,
                robust_z_threshold=self._robust_z_threshold,
            )
            for finding in detector.detect(members):
                finding.anomaly_type = AnomalyType.CONCEPT_HUBNESS
                finding.description = (
                    f"Concept '{concept}' contains an adversarial hub. {finding.description}"
                )
                finding.details = {
                    **finding.details,
                    "concept": concept,
                    "metadata_field": metadata_field,
                }
                findings.append(finding)
        return findings


class ModalityAwareHubnessDetector:
    """Detect hubs inside modality buckets for multimodal retrieval systems."""

    def __init__(
        self,
        k: int = 10,
        hubness_threshold: float = 2.5,
        robust_z_threshold: float = 2.5,
        min_group_size: int = 4,
    ):
        self._k = k
        self._threshold = hubness_threshold
        self._robust_z_threshold = robust_z_threshold
        self._min_group_size = min_group_size

    def detect(
        self,
        vectors: list[EmbeddingVector],
        metadata_field: str = "modality",
    ) -> list[HubnessFinding]:
        findings: list[HubnessFinding] = []
        for modality, members in _partition_vectors(vectors, metadata_field).items():
            if len(members) < self._min_group_size:
                continue
            effective_k = min(self._k, max(1, len(members) // 3))
            detector = HubnessDetector(
                k=effective_k,
                hubness_threshold=self._threshold,
                robust_z_threshold=self._robust_z_threshold,
            )
            for finding in detector.detect(members):
                finding.anomaly_type = AnomalyType.MODALITY_HUBNESS
                finding.description = (
                    f"Modality '{modality}' contains an adversarial hub. {finding.description}"
                )
                finding.details = {
                    **finding.details,
                    "modality": modality,
                    "metadata_field": metadata_field,
                }
                findings.append(finding)
        return findings


class ClusterSpreadDetector:

    def __init__(self, max_spread_ratio: float = 5.0):
        self._max_ratio = max_spread_ratio

    def detect(
        self, vectors: list[EmbeddingVector], labels: dict[str, str] | None = None,
    ) -> list[HubnessFinding]:
        if labels is None:
            labels = {v.vector_id: v.label for v in vectors}

        clusters: dict[str, list[EmbeddingVector]] = {}
        for v in vectors:
            lbl = labels.get(v.vector_id, "unknown")
            clusters.setdefault(lbl, []).append(v)

        findings = []
        spreads: dict[str, float] = {}
        for lbl, members in clusters.items():
            if len(members) < 2:
                continue
            centroid = _mean_vector([m.values for m in members])
            dists = [_euclidean_distance(m.values, centroid) for m in members]
            spread = max(dists) / max(min(dists), 1e-10)
            spreads[lbl] = spread

        if not spreads:
            return []

        mean_spread = sum(spreads.values()) / len(spreads)
        for lbl, spread in spreads.items():
            ratio = spread / max(mean_spread, 1e-10)
            if ratio > self._max_ratio:
                findings.append(HubnessFinding(
                    anomaly_type=AnomalyType.CLUSTER_SPREAD,
                    severity="HIGH",
                    description=f"Cluster '{lbl}' has anomalous spread ratio={ratio:.2f}",
                    vector_ids=[v.vector_id for v in clusters[lbl]],
                    score=ratio,
                    threshold=self._max_ratio,
                    details={"spread": spread, "mean_spread": mean_spread},
                ))
        return findings


class StabilityDetector:

    def __init__(self, perturbation_epsilon: float = 0.01, max_shift: float = 0.1):
        self._epsilon = perturbation_epsilon
        self._max_shift = max_shift

    def detect(self, vectors: list[EmbeddingVector]) -> list[HubnessFinding]:
        findings = []
        for v in vectors:
            perturbed = [x + self._epsilon for x in v.values]
            sim = _cosine_similarity(v.values, perturbed)
            shift = 1.0 - sim
            if shift > self._max_shift:
                findings.append(HubnessFinding(
                    anomaly_type=AnomalyType.STABILITY,
                    severity="MEDIUM",
                    description=f"Vector {v.vector_id} unstable: shift={shift:.4f}",
                    vector_ids=[v.vector_id],
                    score=shift,
                    threshold=self._max_shift,
                ))
        return findings


class NearDuplicateDetector:

    def __init__(self, similarity_threshold: float = 0.999):
        self._threshold = similarity_threshold

    def detect(self, vectors: list[EmbeddingVector]) -> list[HubnessFinding]:
        findings = []
        seen_pairs: set[tuple[str, str]] = set()
        for i, vi in enumerate(vectors):
            for j in range(i + 1, len(vectors)):
                vj = vectors[j]
                sim = _cosine_similarity(vi.values, vj.values)
                if sim > self._threshold:
                    pair = (vi.vector_id, vj.vector_id)
                    if pair not in seen_pairs:
                        seen_pairs.add(pair)
                        findings.append(HubnessFinding(
                            anomaly_type=AnomalyType.NEAR_DUPLICATE,
                            severity="MEDIUM",
                            description=f"Near-duplicate pair: similarity={sim:.6f}",
                            vector_ids=[vi.vector_id, vj.vector_id],
                            score=sim,
                            threshold=self._threshold,
                        ))
        return findings


class DimensionalCollapseDetector:

    def __init__(self, min_effective_dims_ratio: float = 0.1):
        self._min_ratio = min_effective_dims_ratio

    def detect(self, vectors: list[EmbeddingVector]) -> list[HubnessFinding]:
        if not vectors:
            return []
        dim = len(vectors[0].values)
        if dim == 0:
            return []

        dim_variances = []
        for d in range(dim):
            vals = [v.values[d] for v in vectors]
            mean = sum(vals) / len(vals)
            var = sum((x - mean) ** 2 for x in vals) / len(vals)
            dim_variances.append(var)

        total_var = sum(dim_variances)
        if total_var == 0:
            return [HubnessFinding(
                anomaly_type=AnomalyType.DIMENSIONAL_COLLAPSE,
                severity="CRITICAL",
                description="Total variance is zero — complete dimensional collapse",
                score=0.0, threshold=self._min_ratio,
            )]

        active_dims = sum(1 for v in dim_variances if v / total_var > 1e-6)
        ratio = active_dims / dim
        if ratio < self._min_ratio:
            return [HubnessFinding(
                anomaly_type=AnomalyType.DIMENSIONAL_COLLAPSE,
                severity="HIGH",
                description=f"Dimensional collapse: {active_dims}/{dim} active dims ({ratio:.2%})",
                score=ratio,
                threshold=self._min_ratio,
                details={"active_dims": active_dims, "total_dims": dim},
            )]
        return []


class AdversarialHubnessScanner:

    def __init__(self):
        self._hubness = HubnessDetector()
        self._concept = ConceptAwareHubnessDetector()
        self._modality = ModalityAwareHubnessDetector()
        self._cluster = ClusterSpreadDetector()
        self._stability = StabilityDetector()
        self._dedup = NearDuplicateDetector()
        self._collapse = DimensionalCollapseDetector()

    def full_scan(self, vectors: list[EmbeddingVector]) -> list[HubnessFinding]:
        findings = []
        findings.extend(self._hubness.detect(vectors))
        findings.extend(self._cluster.detect(vectors))
        findings.extend(self._stability.detect(vectors))
        findings.extend(self._dedup.detect(vectors))
        findings.extend(self._collapse.detect(vectors))
        if any("concept" in vector.metadata for vector in vectors):
            findings.extend(self.concept_scan(vectors))
        if any("modality" in vector.metadata for vector in vectors):
            findings.extend(self.modality_scan(vectors))
        return findings

    def quick_scan(self, vectors: list[EmbeddingVector]) -> list[HubnessFinding]:
        findings = []
        findings.extend(self._hubness.detect(vectors))
        findings.extend(self._collapse.detect(vectors))
        return findings

    def concept_scan(
        self,
        vectors: list[EmbeddingVector],
        metadata_field: str = "concept",
    ) -> list[HubnessFinding]:
        return self._concept.detect(vectors, metadata_field=metadata_field)

    def modality_scan(
        self,
        vectors: list[EmbeddingVector],
        metadata_field: str = "modality",
    ) -> list[HubnessFinding]:
        return self._modality.detect(vectors, metadata_field=metadata_field)
