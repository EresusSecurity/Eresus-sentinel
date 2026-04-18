"""Differential fuzzing — compare scanner versions for regressions."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Callable

from .base import Payload, FuzzResult

logger = logging.getLogger(__name__)


@dataclass
class DiffResult:
    """Result of differential comparison for a single payload."""
    payload_name: str
    category: str
    results: dict[str, bool] = field(default_factory=dict)
    is_regression: bool = False
    is_improvement: bool = False

    @property
    def is_divergent(self) -> bool:
        vals = list(self.results.values())
        return len(set(vals)) > 1


@dataclass
class DiffReport:
    """Full differential fuzzing report."""
    total_payloads: int = 0
    divergent_count: int = 0
    regressions: list[DiffResult] = field(default_factory=list)
    improvements: list[DiffResult] = field(default_factory=list)
    consistent: int = 0
    scanner_names: list[str] = field(default_factory=list)
    per_scanner: dict[str, dict] = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "total_payloads": self.total_payloads,
            "divergent_count": self.divergent_count,
            "consistent": self.consistent,
            "scanner_names": self.scanner_names,
            "regressions": [
                {
                    "payload": r.payload_name,
                    "category": r.category,
                    "results": r.results,
                }
                for r in self.regressions
            ],
            "improvements": [
                {
                    "payload": r.payload_name,
                    "category": r.category,
                    "results": r.results,
                }
                for r in self.improvements
            ],
            "per_scanner": self.per_scanner,
        }


class DifferentialFuzzer:
    """Compares multiple scanner implementations/versions."""

    def __init__(
        self,
        scanners: dict[str, Callable[[bytes, str], list]],
        baseline: str = "",
    ):
        self._scanners = scanners
        self._baseline = baseline or (list(scanners.keys())[0] if scanners else "")

    def run(self, payloads: list[Payload]) -> DiffReport:
        report = DiffReport(
            total_payloads=len(payloads),
            scanner_names=list(self._scanners.keys()),
        )

        per_scanner: dict[str, dict] = {
            name: {"detected": 0, "missed": 0, "crashed": 0}
            for name in self._scanners
        }

        for payload in payloads:
            diff = DiffResult(
                payload_name=payload.name,
                category=payload.category.value,
            )

            for name, scanner_fn in self._scanners.items():
                try:
                    findings = scanner_fn(payload.data, payload.name)
                    detected = len(findings) > 0
                    diff.results[name] = detected
                    if detected:
                        per_scanner[name]["detected"] += 1
                    else:
                        per_scanner[name]["missed"] += 1
                except Exception:
                    diff.results[name] = False
                    per_scanner[name]["crashed"] += 1

            if diff.is_divergent and payload.is_malicious:
                baseline_detected = diff.results.get(self._baseline, False)

                if baseline_detected and not all(diff.results.values()):
                    diff.is_regression = True
                    report.regressions.append(diff)
                elif not baseline_detected and any(diff.results.values()):
                    diff.is_improvement = True
                    report.improvements.append(diff)

                report.divergent_count += 1
            else:
                report.consistent += 1

        report.per_scanner = per_scanner
        return report

    def save_report(self, report: DiffReport, path: str | Path) -> None:
        p = Path(path)
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(
            json.dumps(report.to_dict(), indent=2, ensure_ascii=False),
            encoding="utf-8",
        )
