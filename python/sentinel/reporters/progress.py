"""
Multi-phase progress reporter for scan pipelines.

Supports console, file, and callback output modes.
"""

from __future__ import annotations

import json
import logging
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional

_log = logging.getLogger("sentinel.reporters.progress")


class Phase(str, Enum):
    INIT = "init"
    DISCOVERY = "discovery"
    SCANNING = "scanning"
    ANALYSIS = "analysis"
    REPORTING = "reporting"
    DONE = "done"


@dataclass
class ProgressEvent:
    phase: Phase
    message: str
    current: int = 0
    total: int = 0
    findings_so_far: int = 0
    elapsed_ms: float = 0.0
    extra: dict = field(default_factory=dict)

    @property
    def pct(self) -> float:
        return (self.current / self.total * 100) if self.total > 0 else 0.0

    def to_dict(self) -> dict:
        return {
            "phase": self.phase.value,
            "message": self.message,
            "current": self.current,
            "total": self.total,
            "pct": round(self.pct, 1),
            "findings": self.findings_so_far,
            "elapsed_ms": round(self.elapsed_ms, 1),
        }


class ProgressReporter:
    """Multi-phase progress reporter with pluggable output."""

    def __init__(
        self,
        callback: Optional[Callable[[ProgressEvent], None]] = None,
        log_file: Optional[str] = None,
        quiet: bool = False,
    ):
        self._callback = callback
        self._log_file = log_file
        self._quiet = quiet
        self._start_time = time.perf_counter()
        self._findings = 0

    def emit(
        self,
        phase: Phase,
        message: str,
        current: int = 0,
        total: int = 0,
        extra: Optional[dict] = None,
    ) -> None:
        elapsed = (time.perf_counter() - self._start_time) * 1000
        event = ProgressEvent(
            phase=phase,
            message=message,
            current=current,
            total=total,
            findings_so_far=self._findings,
            elapsed_ms=elapsed,
            extra=extra or {},
        )

        if not self._quiet:
            pct = f" ({event.pct:.0f}%)" if total > 0 else ""
            _log.info("[%s] %s%s — %d findings, %.0fms",
                      phase.value.upper(), message, pct, self._findings, elapsed)

        if self._callback:
            try:
                self._callback(event)
            except Exception as exc:
                _log.warning("Progress callback error: %s", exc)

        if self._log_file:
            try:
                with open(self._log_file, "a") as f:
                    f.write(json.dumps(event.to_dict()) + "\n")
            except OSError as exc:
                _log.warning("Progress log write error: %s", exc)

    def add_findings(self, count: int) -> None:
        self._findings += count

    def start(self, total_files: int = 0) -> None:
        self.emit(Phase.INIT, "Scan started", total=total_files)

    def discovery(self, files_found: int) -> None:
        self.emit(Phase.DISCOVERY, f"Discovered {files_found} files", total=files_found)

    def scanning(self, current: int, total: int, filename: str = "") -> None:
        msg = f"Scanning {filename}" if filename else f"Scanning file {current}/{total}"
        self.emit(Phase.SCANNING, msg, current=current, total=total)

    def analysis(self, message: str = "Running analysis") -> None:
        self.emit(Phase.ANALYSIS, message)

    def done(self) -> None:
        self.emit(Phase.DONE, f"Complete — {self._findings} total findings")
