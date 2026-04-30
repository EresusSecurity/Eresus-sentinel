"""Generic fuzzer pipeline — generate → mutate → scan → score → store."""

from __future__ import annotations

import logging
import time
from pathlib import Path
from typing import TYPE_CHECKING

from .base import FuzzConfig, FuzzResult, Payload
from .scoring import DetectionScore, ScoringEngine

if TYPE_CHECKING:
    from collections.abc import Callable

logger = logging.getLogger(__name__)


def _safe_payload_filename(name: str) -> str:
    """Return a stable filename segment for persisted fuzz artifacts."""
    safe = "".join(
        char if char.isalnum() or char in {"-", "_", "."} else "_"
        for char in name
    ).strip("._")
    return (safe or "payload")[:120]


class FuzzPipeline:
    """Generic fuzz pipeline: generate → scan → score."""

    def __init__(
        self,
        scanner_fn: Callable[[bytes, str], list],
        config: FuzzConfig | None = None,
    ):
        self._scanner_fn = scanner_fn
        self._config = config or FuzzConfig()
        self._scoring = ScoringEngine()
        self._results: list[FuzzResult] = []
        self._bypasses: list[FuzzResult] = []
        self._false_positives: list[FuzzResult] = []
        self._crashes: list[FuzzResult] = []

    def run(self, payloads: list[Payload]) -> DetectionScore:
        """Run the full pipeline on all payloads."""
        logger.info(
            "Starting fuzz pipeline: %d payloads (%d malicious, %d benign)",
            len(payloads),
            sum(1 for p in payloads if p.is_malicious),
            sum(1 for p in payloads if not p.is_malicious),
        )

        for i, payload in enumerate(payloads):
            result = self._test_one(payload)
            self._results.append(result)
            self._scoring.add_result(result)

            # Track interesting results
            if result.scanner_crashed:
                self._crashes.append(result)
                logger.error(
                    "💥 CRASH [%d/%d]: %s — scanner crashed: %s",
                    i + 1, len(payloads), payload.name, result.error,
                )
            elif result.is_bypass:
                self._bypasses.append(result)
                logger.warning(
                    "⚠ BYPASS [%d/%d]: %s (%s) — scanner missed it!",
                    i + 1, len(payloads), payload.name, payload.category.value,
                )
            elif result.is_false_positive:
                self._false_positives.append(result)
                logger.warning(
                    "⚠ FALSE POSITIVE [%d/%d]: %s flagged as malicious",
                    i + 1, len(payloads), payload.name,
                )

        score = self._scoring.compute()

        # Store results if configured
        if self._config.output_dir:
            report_path = Path(self._config.output_dir) / "fuzz_report.json"
            self._scoring.save_report(report_path)

            # Store bypassed payloads
            if self._bypasses:
                bypass_dir = Path(self._config.output_dir) / "bypasses"
                bypass_dir.mkdir(parents=True, exist_ok=True)
                for r in self._bypasses:
                    filename = _safe_payload_filename(r.payload.name)
                    (bypass_dir / f"{filename}.pkl").write_bytes(r.payload.data)

            # Store false-positive payloads for regression and rule tuning
            if self._false_positives:
                fp_dir = Path(self._config.output_dir) / "false_positives"
                fp_dir.mkdir(parents=True, exist_ok=True)
                for r in self._false_positives:
                    filename = _safe_payload_filename(r.payload.name)
                    (fp_dir / f"{filename}.pkl").write_bytes(r.payload.data)

            # Store crash-inducing payloads
            if self._crashes:
                crash_dir = Path(self._config.output_dir) / "crashes"
                crash_dir.mkdir(parents=True, exist_ok=True)
                for r in self._crashes:
                    filename = _safe_payload_filename(r.payload.name)
                    (crash_dir / f"{filename}.pkl").write_bytes(r.payload.data)

        return score

    def _test_one(self, payload: Payload) -> FuzzResult:
        """Test a single payload through the scanner."""
        result = FuzzResult(payload=payload)

        t0 = time.perf_counter()
        try:
            findings = self._scanner_fn(payload.data, payload.name)
            result.findings_count = len(findings)
            result.detected = len(findings) > 0

            if findings:
                # Find max severity
                severities = {"CRITICAL": 4, "HIGH": 3, "MEDIUM": 2, "LOW": 1}
                max_sev = "LOW"
                for f in findings:
                    sev = getattr(f, "severity", None)
                    if sev:
                        sev_name = sev.name if hasattr(sev, "name") else str(sev)
                        if severities.get(sev_name, 0) > severities.get(max_sev, 0):
                            max_sev = sev_name
                result.max_severity = max_sev

        except Exception as exc:
            result.scanner_crashed = True
            result.error = f"{type(exc).__name__}: {exc}"

        result.detection_time_ms = (time.perf_counter() - t0) * 1000
        return result

    @property
    def results(self) -> list[FuzzResult]:
        return self._results

    @property
    def bypasses(self) -> list[FuzzResult]:
        return self._bypasses

    @property
    def false_positives(self) -> list[FuzzResult]:
        return self._false_positives

    @property
    def crashes(self) -> list[FuzzResult]:
        return self._crashes
