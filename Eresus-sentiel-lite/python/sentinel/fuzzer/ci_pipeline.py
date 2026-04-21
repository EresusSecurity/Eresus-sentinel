"""CI/CD integration — selftest pipeline for GitHub Actions."""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Optional

from .base import FuzzResult, PayloadCategory
from .scoring import ScoringEngine

logger = logging.getLogger(__name__)


@dataclass
class CIConfig:
    min_tpr: float = 0.95
    max_fpr: float = 0.05
    max_detection_time_ms: float = 500.0
    fail_on_bypass: bool = True
    fail_on_crash: bool = True
    output_dir: str = ".sentinel-ci"
    artifact_name: str = "sentinel-fuzz-report"


@dataclass
class CIResult:
    passed: bool
    tpr: float
    fpr: float
    total_payloads: int
    bypasses: int
    crashes: int
    avg_detection_time_ms: float
    violations: list[str] = field(default_factory=list)
    exit_code: int = 0


class CIPipeline:
    """Continuous integration selftest pipeline."""

    def __init__(self, config: Optional[CIConfig] = None):
        self._config = config or CIConfig()

    def evaluate(self, results: list[FuzzResult]) -> CIResult:
        engine = ScoringEngine()
        scores = engine.score(results)

        tpr = scores.get("tpr", 0.0)
        fpr = scores.get("fpr", 0.0)
        bypasses = sum(1 for r in results if r.is_bypass)
        crashes = sum(1 for r in results if r.scanner_crashed)
        times = [r.detection_time_ms for r in results if r.detection_time_ms > 0]
        avg_time = sum(times) / len(times) if times else 0.0

        violations = []

        if tpr < self._config.min_tpr:
            violations.append(f"TPR {tpr:.1%} < minimum {self._config.min_tpr:.1%}")

        if fpr > self._config.max_fpr:
            violations.append(f"FPR {fpr:.1%} > maximum {self._config.max_fpr:.1%}")

        if avg_time > self._config.max_detection_time_ms:
            violations.append(f"Avg detection {avg_time:.1f}ms > max {self._config.max_detection_time_ms:.1f}ms")

        if self._config.fail_on_bypass and bypasses > 0:
            violations.append(f"{bypasses} bypasses detected")

        if self._config.fail_on_crash and crashes > 0:
            violations.append(f"{crashes} scanner crashes")

        passed = len(violations) == 0

        return CIResult(
            passed=passed,
            tpr=tpr,
            fpr=fpr,
            total_payloads=len(results),
            bypasses=bypasses,
            crashes=crashes,
            avg_detection_time_ms=avg_time,
            violations=violations,
            exit_code=0 if passed else 1,
        )

    def save_report(self, result: CIResult, output_dir: Optional[str] = None) -> Path:
        out = Path(output_dir or self._config.output_dir)
        out.mkdir(parents=True, exist_ok=True)
        report_path = out / f"ci-report-{int(time.time())}.json"
        report_path.write_text(
            json.dumps({
                "passed": result.passed,
                "tpr": result.tpr,
                "fpr": result.fpr,
                "total_payloads": result.total_payloads,
                "bypasses": result.bypasses,
                "crashes": result.crashes,
                "avg_detection_time_ms": result.avg_detection_time_ms,
                "violations": result.violations,
                "exit_code": result.exit_code,
            }, indent=2),
            encoding="utf-8",
        )
        logger.info("CI report saved to %s", report_path)
        return report_path

    @staticmethod
    def generate_github_actions_yaml() -> str:
        """Generate a GitHub Actions workflow yaml."""
        return """name: Sentinel Selftest
on:
  push:
    branches: [main]
  pull_request:
    branches: [main]

jobs:
  sentinel-fuzz:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4

      - name: Set up Python
        uses: actions/setup-python@v5
        with:
          python-version: '3.11'

      - name: Install dependencies
        run: pip install -e ".[dev]"

      - name: Run Sentinel selftest
        run: python -m sentinel.fuzzer.ci_runner

      - name: Upload fuzz report
        if: always()
        uses: actions/upload-artifact@v4
        with:
          name: sentinel-fuzz-report
          path: .sentinel-ci/
"""

    @staticmethod
    def generate_pre_commit_hook() -> str:
        """Generate a pre-commit hook script."""
        return """#!/usr/bin/env bash
set -e
echo "Running Sentinel selftest..."
python -m sentinel.fuzzer.ci_runner --quick
echo "Sentinel selftest passed."
"""


class BaselineTracker:
    """Tracks regression against a known-good baseline."""

    def __init__(self, baseline_path: str | Path):
        self._path = Path(baseline_path)
        self._baseline: dict = {}
        if self._path.exists():
            self._baseline = json.loads(self._path.read_text(encoding="utf-8"))

    def save_baseline(self, result: CIResult) -> None:
        self._baseline = {
            "tpr": result.tpr,
            "fpr": result.fpr,
            "total_payloads": result.total_payloads,
            "bypasses": result.bypasses,
            "timestamp": int(time.time()),
        }
        self._path.parent.mkdir(parents=True, exist_ok=True)
        self._path.write_text(
            json.dumps(self._baseline, indent=2),
            encoding="utf-8",
        )

    def check_regression(self, current: CIResult) -> list[str]:
        if not self._baseline:
            return []

        regressions = []
        baseline_tpr = self._baseline.get("tpr", 0.0)
        baseline_bypasses = self._baseline.get("bypasses", 0)

        if current.tpr < baseline_tpr - 0.01:
            regressions.append(
                f"TPR regressed: {current.tpr:.1%} (was {baseline_tpr:.1%})"
            )

        if current.bypasses > baseline_bypasses:
            regressions.append(
                f"New bypasses: {current.bypasses} (was {baseline_bypasses})"
            )

        return regressions
