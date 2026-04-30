"""Category risk rollups and severity mapping for redteam results."""
from __future__ import annotations

from dataclasses import dataclass, field
from enum import Enum
from typing import Any


class RiskLevel(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class RiskScore:
    category: str
    level: RiskLevel
    score: float  # 0.0 - 10.0
    details: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class RiskReport:
    scores: list[RiskScore] = field(default_factory=list)

    @property
    def overall_level(self) -> RiskLevel:
        if not self.scores:
            return RiskLevel.INFO
        return max(self.scores, key=lambda s: s.score).level

    @property
    def overall_score(self) -> float:
        if not self.scores:
            return 0.0
        return max(s.score for s in self.scores)

    def by_level(self, level: RiskLevel) -> list[RiskScore]:
        return [s for s in self.scores if s.level == level]


_SEVERITY_THRESHOLDS = [
    (9.0, RiskLevel.CRITICAL),
    (7.0, RiskLevel.HIGH),
    (4.0, RiskLevel.MEDIUM),
    (2.0, RiskLevel.LOW),
    (0.0, RiskLevel.INFO),
]


def score_to_level(score: float) -> RiskLevel:
    for threshold, level in _SEVERITY_THRESHOLDS:
        if score >= threshold:
            return level
    return RiskLevel.INFO


def compute_category_risk(
    category: str,
    finding_scores: list[float],
    weights: dict[str, float] | None = None,
) -> RiskScore:
    """Compute risk for a single category from finding scores."""
    if not finding_scores:
        return RiskScore(category=category, level=RiskLevel.INFO, score=0.0)

    weight = (weights or {}).get(category, 1.0)
    max_score = max(finding_scores)
    avg_score = sum(finding_scores) / len(finding_scores)
    combined = max_score * 0.7 + avg_score * 0.3
    weighted = min(combined * weight, 10.0)

    return RiskScore(
        category=category,
        level=score_to_level(weighted),
        score=round(weighted, 2),
        details=f"{len(finding_scores)} findings, max={max_score:.1f}, avg={avg_score:.1f}",
        metadata={
            "max": max_score, "avg": avg_score,
            "count": len(finding_scores), "weight": weight,
        },
    )


def rollup_risk(category_scores: list[RiskScore]) -> RiskReport:
    """Roll up category-level scores into a risk report."""
    return RiskReport(scores=sorted(category_scores, key=lambda s: -s.score))
