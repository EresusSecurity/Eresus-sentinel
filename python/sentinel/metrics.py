"""
Eresus Sentinel — Prometheus / OpenTelemetry Metrics.

Export scanner performance metrics for observability dashboards.

Counters:
  sentinel_scan_total{scanner, scanner_type, action}
  sentinel_findings_total{scanner, severity}

Histograms:
  sentinel_scan_duration_seconds{scanner, scanner_type}
  sentinel_risk_score{scanner}

Gauges:
  sentinel_active_scanners{scanner_type}
  sentinel_policy_version{}

Usage:
    from sentinel.metrics import MetricsCollector
    metrics = MetricsCollector()

    # Instrument a scan
    with metrics.track("toxicity", "output"):
        result = scanner.scan(prompt, output)
    metrics.record_result("toxicity", "output", result)

    # Export
    print(metrics.export_prometheus())
"""

from __future__ import annotations

import logging
import threading
import time
from contextlib import contextmanager
from dataclasses import dataclass, field
from typing import Generator

logger = logging.getLogger(__name__)


@dataclass
class _CounterData:
    """Internal counter storage."""
    values: dict[str, float] = field(default_factory=dict)

    def inc(self, labels: str, amount: float = 1.0) -> None:
        self.values[labels] = self.values.get(labels, 0.0) + amount

    def get(self, labels: str) -> float:
        return self.values.get(labels, 0.0)


@dataclass
class _HistogramData:
    """Internal histogram storage (simple bucketed)."""
    buckets: list[float] = field(default_factory=lambda: [
        0.001, 0.005, 0.01, 0.025, 0.05, 0.1, 0.25, 0.5, 1.0, 2.5, 5.0, 10.0,
    ])
    counts: dict[str, list[int]] = field(default_factory=dict)
    sums: dict[str, float] = field(default_factory=dict)
    totals: dict[str, int] = field(default_factory=dict)

    def observe(self, labels: str, value: float) -> None:
        if labels not in self.counts:
            self.counts[labels] = [0] * len(self.buckets)
            self.sums[labels] = 0.0
            self.totals[labels] = 0

        self.sums[labels] += value
        self.totals[labels] += 1
        for i, b in enumerate(self.buckets):
            if value <= b:
                self.counts[labels][i] += 1


class MetricsCollector:
    """
    Lightweight metrics collector compatible with Prometheus exposition format.

    No external dependencies — generates Prometheus text format directly.
    Can also integrate with OpenTelemetry SDK if available.

    Usage:
        metrics = MetricsCollector()
        metrics.record_result("toxicity", "output", scan_result)
        print(metrics.export_prometheus())
    """

    def __init__(self):
        self._lock = threading.Lock()

        # Counters
        self._scan_total = _CounterData()
        self._findings_total = _CounterData()

        # Histograms
        self._duration = _HistogramData()
        self._risk_scores = _HistogramData(
            buckets=[0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
        )

        # Gauges
        self._active_scanners: dict[str, int] = {}
        self._policy_version: str = ""

    @contextmanager
    def track(self, scanner: str, scanner_type: str = "output") -> Generator[None, None, None]:
        """Context manager to time a scan operation."""
        start = time.perf_counter()
        try:
            yield
        finally:
            elapsed = time.perf_counter() - start
            labels = f'scanner="{scanner}",scanner_type="{scanner_type}"'
            with self._lock:
                self._duration.observe(labels, elapsed)

    def record_result(
        self,
        scanner: str,
        scanner_type: str,
        result,  # ScanResult
        duration_seconds: float | None = None,
    ) -> None:
        """Record metrics from a ScanResult."""
        action = result.action.value if hasattr(result.action, "value") else str(result.action)
        scan_labels = f'scanner="{scanner}",scanner_type="{scanner_type}",action="{action}"'
        risk_labels = f'scanner="{scanner}"'

        with self._lock:
            self._scan_total.inc(scan_labels)
            self._risk_scores.observe(risk_labels, result.risk_score)

            for finding in result.findings:
                sev = (
                    finding.severity.value
                    if hasattr(finding.severity, "value")
                    else str(finding.severity)
                )
                f_labels = f'scanner="{scanner}",severity="{sev}"'
                self._findings_total.inc(f_labels)

            if duration_seconds is not None:
                dur_labels = f'scanner="{scanner}",scanner_type="{scanner_type}"'
                self._duration.observe(dur_labels, duration_seconds)

    def set_active_scanners(self, scanner_type: str, count: int) -> None:
        """Set the gauge for active scanner count."""
        with self._lock:
            self._active_scanners[scanner_type] = count

    def set_policy_version(self, version: str) -> None:
        """Set the current policy version gauge."""
        self._policy_version = version

    def export_prometheus(self) -> str:
        """Export all metrics in Prometheus text exposition format."""
        lines: list[str] = []

        with self._lock:
            # scan_total counter
            lines.append("# HELP sentinel_scan_total Total number of scans")
            lines.append("# TYPE sentinel_scan_total counter")
            for labels, value in sorted(self._scan_total.values.items()):
                lines.append(f"sentinel_scan_total{{{labels}}} {value}")

            # findings_total counter
            lines.append("# HELP sentinel_findings_total Total security findings")
            lines.append("# TYPE sentinel_findings_total counter")
            for labels, value in sorted(self._findings_total.values.items()):
                lines.append(f"sentinel_findings_total{{{labels}}} {value}")

            # duration histogram
            lines.append("# HELP sentinel_scan_duration_seconds Scan duration")
            lines.append("# TYPE sentinel_scan_duration_seconds histogram")
            for labels in sorted(self._duration.counts.keys()):
                counts = self._duration.counts[labels]
                for i, bucket in enumerate(self._duration.buckets):
                    lines.append(
                        "sentinel_scan_duration_seconds_bucket"
                        f'{{{labels},le="{bucket}"}} {counts[i]}'
                    )
                lines.append(
                    "sentinel_scan_duration_seconds_bucket"
                    f'{{{labels},le="+Inf"}} {self._duration.totals[labels]}'
                )
                lines.append(
                    "sentinel_scan_duration_seconds_sum"
                    f"{{{labels}}} {self._duration.sums[labels]:.6f}"
                )
                lines.append(
                    "sentinel_scan_duration_seconds_count"
                    f"{{{labels}}} {self._duration.totals[labels]}"
                )

            # risk_score histogram
            lines.append("# HELP sentinel_risk_score Risk scores distribution")
            lines.append("# TYPE sentinel_risk_score histogram")
            for labels in sorted(self._risk_scores.counts.keys()):
                counts = self._risk_scores.counts[labels]
                for i, bucket in enumerate(self._risk_scores.buckets):
                    lines.append(
                        f'sentinel_risk_score_bucket{{{labels},le="{bucket}"}} {counts[i]}'
                    )
                lines.append(
                    "sentinel_risk_score_bucket"
                    f'{{{labels},le="+Inf"}} {self._risk_scores.totals[labels]}'
                )
                lines.append(
                    "sentinel_risk_score_sum"
                    f"{{{labels}}} {self._risk_scores.sums[labels]:.4f}"
                )
                lines.append(
                    "sentinel_risk_score_count"
                    f"{{{labels}}} {self._risk_scores.totals[labels]}"
                )

            # Active scanners gauge
            lines.append("# HELP sentinel_active_scanners Currently active scanners")
            lines.append("# TYPE sentinel_active_scanners gauge")
            for stype, count in sorted(self._active_scanners.items()):
                lines.append(f'sentinel_active_scanners{{scanner_type="{stype}"}} {count}')

            # Policy version gauge
            if self._policy_version:
                lines.append("# HELP sentinel_policy_version Current policy version")
                lines.append("# TYPE sentinel_policy_version gauge")
                lines.append(f'sentinel_policy_version{{version="{self._policy_version}"}} 1')

        return "\n".join(lines) + "\n"

    def summary(self) -> dict:
        """Return a summary dict for debugging."""
        with self._lock:
            return {
                "total_scans": sum(self._scan_total.values.values()),
                "total_findings": sum(self._findings_total.values.values()),
                "scanners_tracked": len(self._duration.totals),
                "policy_version": self._policy_version,
            }

    def avg_latency(self, scanner: str, scanner_type: str = "output") -> float:
        """Return average latency in seconds for a scanner."""
        labels = f'scanner="{scanner}",scanner_type="{scanner_type}"'
        with self._lock:
            total = self._duration.totals.get(labels, 0)
            total_sum = self._duration.sums.get(labels, 0.0)
            return total_sum / total if total > 0 else 0.0

    def block_rate(self) -> float:
        """Return the overall block rate (0.0 - 1.0)."""
        with self._lock:
            total = sum(self._scan_total.values.values())
            blocked = sum(v for k, v in self._scan_total.values.items() if 'action="block"' in k)
            return blocked / total if total > 0 else 0.0

    def check_alerts(
        self,
        max_latency_seconds: float = 5.0,
        max_block_rate: float = 0.5,
    ) -> list[str]:
        """
        Check for operational alerts.

        Returns list of alert strings if thresholds are exceeded.
        """
        alerts = []

        # Latency alerts
        with self._lock:
            for labels, total_sum in self._duration.sums.items():
                total_count = self._duration.totals.get(labels, 1)
                avg = total_sum / total_count
                if avg > max_latency_seconds:
                    alerts.append(
                        f"LATENCY: {labels} avg={avg:.3f}s exceeds threshold {max_latency_seconds}s"
                    )

        # Block rate alert
        rate = self.block_rate()
        if rate > max_block_rate:
            alerts.append(
                f"BLOCK_RATE: {rate:.1%} exceeds threshold {max_block_rate:.1%}"
            )

        return alerts

    def export_json(self) -> dict:
        """Export all metrics as a JSON-compatible dict."""
        with self._lock:
            return {
                "counters": {
                    "scan_total": dict(self._scan_total.values),
                    "findings_total": dict(self._findings_total.values),
                },
                "histograms": {
                    "duration_sums": dict(self._duration.sums),
                    "duration_counts": dict(self._duration.totals),
                    "risk_sums": dict(self._risk_scores.sums),
                    "risk_counts": dict(self._risk_scores.totals),
                },
                "gauges": {
                    "active_scanners": dict(self._active_scanners),
                    "policy_version": self._policy_version,
                },
            }

    def reset(self) -> None:
        """Reset all metrics counters."""
        with self._lock:
            self._scan_total = _CounterData()
            self._findings_total = _CounterData()
            self._duration = _HistogramData()
            self._risk_scores = _HistogramData(
                buckets=[0.0, 0.1, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0],
            )
            self._active_scanners.clear()
            logger.info("Metrics reset")

    def try_register_otel(self) -> bool:
        """
        Attempt to register with OpenTelemetry SDK if available.

        If opentelemetry-api is installed, creates real OTEL instruments.
        Returns True if OTEL integration was successful.
        """
        try:
            from opentelemetry import metrics as otel_metrics
            meter = otel_metrics.get_meter("sentinel", "0.4.0")

            self._otel_scan_counter = meter.create_counter(
                "sentinel.scan.total",
                description="Total number of scans",
            )
            self._otel_duration = meter.create_histogram(
                "sentinel.scan.duration",
                unit="s",
                description="Scan duration in seconds",
            )
            logger.info("OpenTelemetry integration enabled")
            return True
        except ImportError:
            logger.debug("OpenTelemetry not available — using built-in metrics only")
            return False
