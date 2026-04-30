"""Differential fuzzing — compare scanner versions for regressions."""

from __future__ import annotations

import json
import logging
import subprocess
import tempfile
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import TYPE_CHECKING, Any

if TYPE_CHECKING:
    from .base import Payload

logger = logging.getLogger(__name__)

ScannerFn = Callable[[bytes, str], list[Any]]


@dataclass(frozen=True)
class FunctionScannerAdapter:
    """Name a Python scanner callable for differential fuzzing."""

    name: str
    scanner: ScannerFn

    def scan(self, data: bytes, source: str) -> list[Any]:
        return self.scanner(data, source)


@dataclass(frozen=True)
class SubprocessScannerAdapter:
    """Run an external scanner CLI against each payload via a temp file.

    ``command`` must be an argv list without the target file path. The adapter
    appends a temp file containing the payload and treats configured exit codes
    or output markers as detection.
    """

    name: str
    command: list[str]
    suffix: str = ".bin"
    timeout_seconds: float = 10.0
    detected_exit_codes: tuple[int, ...] = (1,)
    detected_markers: tuple[str, ...] = ("CRITICAL", "HIGH", "malicious", "unsafe")

    def scan(self, data: bytes, source: str) -> list[dict[str, str]]:
        with tempfile.NamedTemporaryFile(suffix=self.suffix, delete=False) as tmp:
            tmp.write(data)
            tmp_path = Path(tmp.name)

        try:
            proc = subprocess.run(
                [*self.command, str(tmp_path)],
                capture_output=True,
                check=False,
                text=True,
                timeout=self.timeout_seconds,
            )
        finally:
            tmp_path.unlink(missing_ok=True)

        output = f"{proc.stdout}\n{proc.stderr}"
        detected = proc.returncode in self.detected_exit_codes or any(
            marker in output for marker in self.detected_markers
        )
        if not detected:
            return []
        return [{
            "scanner": self.name,
            "source": source,
            "returncode": str(proc.returncode),
            "evidence": output[:2000],
        }]


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
        scanners: dict[str, ScannerFn | Any] | list[Any],
        baseline: str = "",
    ):
        self._scanners = self._normalize_scanners(scanners)
        self._baseline = baseline or (
            list(self._scanners.keys())[0] if self._scanners else ""
        )

    @staticmethod
    def _normalize_scanners(
        scanners: dict[str, ScannerFn | Any] | list[Any],
    ) -> dict[str, ScannerFn]:
        normalized: dict[str, ScannerFn] = {}
        if isinstance(scanners, dict):
            for name, scanner in scanners.items():
                normalized[name] = scanner.scan if hasattr(scanner, "scan") else scanner
            return normalized

        for scanner in scanners:
            name = getattr(scanner, "name", scanner.__class__.__name__)
            normalized[name] = scanner.scan
        return normalized

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
