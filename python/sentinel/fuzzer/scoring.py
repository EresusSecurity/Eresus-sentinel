"""Detection score engine — measures scanner effectiveness."""

from __future__ import annotations

import json
import logging
from dataclasses import dataclass, field
from datetime import datetime, timezone
from pathlib import Path
from typing import TYPE_CHECKING

if TYPE_CHECKING:
    from .base import FuzzResult

logger = logging.getLogger(__name__)


@dataclass
class DetectionScore:
    """Aggregate detection metrics from a fuzzing session."""

    # Counts
    total_samples: int = 0
    malicious_samples: int = 0
    benign_samples: int = 0

    # Detection
    true_positives: int = 0       # malicious + detected
    false_positives: int = 0      # benign + detected
    true_negatives: int = 0       # benign + NOT detected
    false_negatives: int = 0      # malicious + NOT detected (BYPASS!)

    # Crashes
    scanner_crashes: int = 0

    # Bypasses (the most important list)
    bypassed_payloads: list[str] = field(default_factory=list)
    false_positive_payloads: list[str] = field(default_factory=list)
    crashed_payloads: list[str] = field(default_factory=list)

    # Category breakdown
    category_stats: dict[str, dict[str, int]] = field(default_factory=dict)

    # Timing
    total_time_ms: float = 0.0
    avg_scan_time_ms: float = 0.0

    # Metadata
    timestamp: str = ""
    fuzzer_version: str = "sentinel-fuzzer-0.1.0"

    @property
    def tpr(self) -> float:
        """True Positive Rate (sensitivity / recall)."""
        if self.malicious_samples == 0:
            return 0.0
        return self.true_positives / self.malicious_samples

    @property
    def fpr(self) -> float:
        """False Positive Rate."""
        if self.benign_samples == 0:
            return 0.0
        return self.false_positives / self.benign_samples

    @property
    def precision(self) -> float:
        """Precision: TP / (TP + FP)."""
        total_detected = self.true_positives + self.false_positives
        if total_detected == 0:
            return 0.0
        return self.true_positives / total_detected

    @property
    def f1(self) -> float:
        """F1 score: harmonic mean of precision and recall."""
        p, r = self.precision, self.tpr
        if p + r == 0:
            return 0.0
        return 2 * (p * r) / (p + r)

    @property
    def bypass_rate(self) -> float:
        """Percentage of malicious payloads that evaded detection."""
        if self.malicious_samples == 0:
            return 0.0
        return self.false_negatives / self.malicious_samples

    @property
    def mcc(self) -> float:
        """Matthews Correlation Coefficient — balanced metric for imbalanced datasets."""
        tp, fp = self.true_positives, self.false_positives
        tn, fn = self.true_negatives, self.false_negatives
        denom = ((tp + fp) * (tp + fn) * (tn + fp) * (tn + fn)) ** 0.5
        if denom == 0:
            return 0.0
        return (tp * tn - fp * fn) / denom

    def to_dict(self) -> dict:
        return {
            "total_samples": self.total_samples,
            "malicious_samples": self.malicious_samples,
            "benign_samples": self.benign_samples,
            "true_positives": self.true_positives,
            "false_positives": self.false_positives,
            "true_negatives": self.true_negatives,
            "false_negatives": self.false_negatives,
            "scanner_crashes": self.scanner_crashes,
            "tpr": round(self.tpr, 4),
            "fpr": round(self.fpr, 4),
            "precision": round(self.precision, 4),
            "f1": round(self.f1, 4),
            "mcc": round(self.mcc, 4),
            "bypass_rate": round(self.bypass_rate, 4),
            "bypassed_payloads": self.bypassed_payloads,
            "false_positive_payloads": self.false_positive_payloads,
            "crashed_payloads": self.crashed_payloads,
            "category_stats": self.category_stats,
            "total_time_ms": round(self.total_time_ms, 2),
            "avg_scan_time_ms": round(self.avg_scan_time_ms, 2),
            "timestamp": self.timestamp,
            "fuzzer_version": self.fuzzer_version,
        }


class ScoringEngine:
    """Aggregates FuzzResults into DetectionScore with category breakdown."""

    def __init__(self) -> None:
        self._results: list[FuzzResult] = []

    def add_result(self, result: FuzzResult) -> None:
        self._results.append(result)

    def compute(self) -> DetectionScore:
        score = DetectionScore(
            timestamp=datetime.now(timezone.utc).isoformat(),
        )

        total_time = 0.0

        for r in self._results:
            score.total_samples += 1
            total_time += r.detection_time_ms
            cat = r.payload.category.value

            # Init category stats
            if cat not in score.category_stats:
                score.category_stats[cat] = {
                    "total": 0, "detected": 0, "bypassed": 0
                }
            score.category_stats[cat]["total"] += 1

            if r.scanner_crashed:
                score.scanner_crashes += 1
                score.crashed_payloads.append(r.payload.name)
                continue

            if r.payload.is_malicious:
                score.malicious_samples += 1
                if r.detected:
                    score.true_positives += 1
                    score.category_stats[cat]["detected"] += 1
                else:
                    score.false_negatives += 1
                    score.bypassed_payloads.append(r.payload.name)
                    score.category_stats[cat]["bypassed"] += 1
            else:
                score.benign_samples += 1
                if r.detected:
                    score.false_positives += 1
                    score.false_positive_payloads.append(r.payload.name)
                    score.category_stats[cat]["detected"] += 1
                else:
                    score.true_negatives += 1

        score.total_time_ms = total_time
        if score.total_samples > 0:
            score.avg_scan_time_ms = total_time / score.total_samples

        return score

    def save_report(self, path: str | Path) -> DetectionScore:
        """Compute score and save JSON report."""
        score = self.compute()
        report_path = Path(path)
        report_path.parent.mkdir(parents=True, exist_ok=True)
        report_path.write_text(
            json.dumps(score.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
        logger.info("Scoring report saved to %s", report_path)
        return score
