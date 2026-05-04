"""Model provenance scanner and pairwise comparison helpers."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from .database import FingerprintDatabase
from .signals import ProvenanceSignal, extract_signals, signal_similarity, weighted_score


@dataclass(frozen=True)
class ProvenanceReport:
    """Result of a model lineage scan."""

    target: str
    verdict: str
    pipeline_score: float
    signals: dict[str, ProvenanceSignal]
    matches: list[dict[str, Any]]
    threshold: float

    def to_dict(self) -> dict[str, Any]:
        return {
            "schema_version": "provenance.report.v1",
            "target": self.target,
            "verdict": self.verdict,
            "pipeline_score": round(self.pipeline_score, 6),
            "threshold": self.threshold,
            "signals": {key: signal.to_dict() for key, signal in self.signals.items()},
            "matches": self.matches,
            "summary": {
                "target": self.target,
                "verdict": self.verdict,
                "pipeline_score": round(self.pipeline_score, 6),
                "top_match": self.matches[0]["model_id"] if self.matches else None,
                "match_count": len(self.matches),
                "signal_coverage": sum(1 for signal in self.signals.values() if signal.confidence > 0.0),
            },
        }


class ModelProvenanceScanner:
    """Extract and match local model fingerprints against a reference DB."""

    def __init__(self, database: FingerprintDatabase | None = None) -> None:
        self.database = database or FingerprintDatabase()

    def scan(self, model_path: str | Path, *, top_k: int = 5, threshold: float = 0.5) -> ProvenanceReport:
        target = Path(model_path)
        signals = extract_signals(target)
        matches = self.database.match(signals, top_k=top_k)
        score = float(matches[0]["score"]) if matches else 0.0
        verdict = _verdict(score, threshold, signals)
        return ProvenanceReport(
            target=str(target),
            verdict=verdict,
            pipeline_score=score,
            signals=signals,
            matches=matches,
            threshold=threshold,
        )


def compare_models(left: str | Path, right: str | Path) -> dict[str, Any]:
    """Compare two local models head-to-head without a reference DB."""
    left_signals = extract_signals(left)
    right_signals = extract_signals(right)
    similarities = signal_similarity(left_signals, right_signals)
    score = weighted_score(similarities)
    return {
        "schema_version": "provenance.compare.v1",
        "model_a": str(left),
        "model_b": str(right),
        "pipeline_score": round(score, 6),
        "verdict": "related" if score >= 0.65 else "possibly_related" if score >= 0.4 else "different",
        "signals": {key: round(value, 6) for key, value in similarities.items()},
        "summary": {
            "pipeline_score": round(score, 6),
            "verdict": "related" if score >= 0.65 else "possibly_related" if score >= 0.4 else "different",
            "signal_count": len(similarities),
        },
    }


def _verdict(score: float, threshold: float, signals: dict[str, ProvenanceSignal]) -> str:
    coverage = sum(1 for signal in signals.values() if signal.confidence > 0.0)
    if coverage < 2:
        return "unknown"
    if score >= max(threshold, 0.75):
        return "matched"
    if score >= threshold:
        return "likely_related"
    if score >= 0.25:
        return "weak_match"
    return "unknown"
