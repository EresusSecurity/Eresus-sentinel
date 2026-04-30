"""Trend tracker — statistical monitoring of detection metrics across fuzzing runs.

Records per-session metric snapshots and provides:
  • **Threshold-based alerts** — configurable per-metric thresholds trigger
    ``TrendAlert`` objects when a metric degrades significantly.
  • **Moving average** — exponential and simple moving averages to smooth noise.
  • **Trend direction** — linear regression slope over a window to detect
    gradual drift (not just step changes).
  • **Anomaly detection** — Z-score based spike/drop detection.
  • **JSONL persistence** — each snapshot is appended to an audit log.
  • **Report generation** — render a text summary or JSON report for CI artefacts.

Typical CI usage::

    tracker = TrendTracker("/ci/trend.jsonl")
    alerts = tracker.record("run-abc", detection_score)
    if any(a.blocking for a in alerts):
        sys.exit(1)
"""

from __future__ import annotations

import json
import logging
import statistics
import time
from dataclasses import asdict, dataclass, field
from pathlib import Path
from typing import Optional

logger = logging.getLogger(__name__)


# ---------------------------------------------------------------------------
# Data models
# ---------------------------------------------------------------------------

@dataclass
class MetricSnapshot:
    """A single session's detection metrics."""
    timestamp: float
    session_id: str
    tpr: float          # True Positive Rate (Recall)
    fpr: float          # False Positive Rate
    f1: float           # F1 score
    bypass_rate: float  # bypass_count / total_payloads
    total: int          # total payloads tested
    mcc: float = 0.0   # Matthews Correlation Coefficient (optional)
    tags: list[str] = field(default_factory=list)

    def to_dict(self) -> dict:
        return asdict(self)

    @classmethod
    def from_dict(cls, d: dict) -> "MetricSnapshot":
        valid = {k: v for k, v in d.items() if k in cls.__dataclass_fields__}
        return cls(**valid)


@dataclass
class TrendAlert:
    """A metric change that exceeded a configured threshold."""
    metric: str
    previous: float
    current: float
    delta: float
    threshold: float
    direction: str      # "drop" | "spike"
    session_id: str = ""
    blocking: bool = False    # True for CRITICAL metrics (tpr, f1)

    def __str__(self) -> str:
        marker = "[BLOCKING]" if self.blocking else "[WARNING]"
        return (
            f"{marker} TREND ALERT — {self.metric} {self.direction}: "
            f"{self.previous:.4f} → {self.current:.4f} "
            f"(Δ={self.delta:+.4f}, threshold=±{self.threshold:.4f})"
        )


# ---------------------------------------------------------------------------
# Trend analysis helpers
# ---------------------------------------------------------------------------

def _ema(values: list[float], alpha: float = 0.3) -> float:
    """Exponential moving average of *values*."""
    if not values:
        return 0.0
    ema = values[0]
    for v in values[1:]:
        ema = alpha * v + (1 - alpha) * ema
    return ema


def _sma(values: list[float], window: int = 5) -> float:
    """Simple moving average over the last *window* values."""
    recent = values[-window:] if len(values) >= window else values
    return sum(recent) / len(recent) if recent else 0.0


def _linear_slope(values: list[float]) -> float:
    """Slope of least-squares line through [0..n-1, values]."""
    n = len(values)
    if n < 2:
        return 0.0
    x_mean = (n - 1) / 2
    y_mean = sum(values) / n
    num = sum((i - x_mean) * (v - y_mean) for i, v in enumerate(values))
    den = sum((i - x_mean) ** 2 for i in range(n))
    return num / den if den else 0.0


def _zscore(value: float, history: list[float]) -> float:
    """Z-score of *value* relative to *history*."""
    if len(history) < 2:
        return 0.0
    mu = statistics.mean(history)
    sigma = statistics.stdev(history)
    if sigma == 0:
        return 0.0
    return (value - mu) / sigma


# ---------------------------------------------------------------------------
# TrendTracker
# ---------------------------------------------------------------------------

class TrendTracker:
    """Appends metric snapshots and alerts when a metric degrades beyond a threshold.

    Args:
        history_path:   JSONL file for persistent snapshot storage.
        thresholds:     Per-metric alert thresholds (absolute change).
                        Defaults to ``DEFAULTS``.
        window:         Window size for moving average and slope computation.
        zscore_alert:   Trigger anomaly alert when |z-score| exceeds this value.
        blocking_metrics: Metrics that produce ``TrendAlert.blocking=True``.

    Example::

        tracker = TrendTracker("trend.jsonl", thresholds={"tpr": 0.03})
        alerts = tracker.record("session-1", score_obj)
        for a in alerts:
            print(a)
    """

    DEFAULTS: dict[str, float] = {
        "tpr": 0.02,          # alert if TPR drops by >2 pp
        "fpr": 0.02,          # alert if FPR spikes by >2 pp
        "f1": 0.02,           # alert if F1 drops by >2 pp
        "bypass_rate": 0.01,  # alert if bypass rate spikes by >1 pp
        "mcc": 0.03,          # alert if MCC drops by >3 pp
    }

    BLOCKING_METRICS: frozenset[str] = frozenset({"tpr", "f1"})

    def __init__(
        self,
        history_path: str | Path,
        thresholds: Optional[dict[str, float]] = None,
        window: int = 10,
        zscore_alert: float = 3.0,
        blocking_metrics: Optional[frozenset] = None,
    ):
        self._path = Path(history_path)
        self._thresholds = {**self.DEFAULTS, **(thresholds or {})}
        self._window = window
        self._zscore_alert = zscore_alert
        self._blocking = blocking_metrics if blocking_metrics is not None else self.BLOCKING_METRICS
        self._snapshots: list[MetricSnapshot] = []
        self._load()

    # ── Recording ───────────────────────────────────────────────────

    def record(self, session_id: str, score: object, tags: Optional[list[str]] = None) -> list[TrendAlert]:
        """Record metrics from a score object and return any threshold alerts.

        The *score* object is read via ``getattr`` — compatible with any object
        exposing tpr, fpr, f1, bypass_rate, total_samples, and optionally mcc.
        """
        snap = MetricSnapshot(
            timestamp=time.time(),
            session_id=session_id,
            tpr=getattr(score, "tpr", 0.0),
            fpr=getattr(score, "fpr", 0.0),
            f1=getattr(score, "f1", 0.0),
            bypass_rate=getattr(score, "bypass_rate", 0.0),
            total=getattr(score, "total_samples", 0),
            mcc=getattr(score, "mcc", 0.0),
            tags=tags or [],
        )
        alerts = []
        if len(self._snapshots) >= 1:
            alerts = self._check_threshold_alerts(snap)
        anomaly_alerts = self._check_anomaly_alerts(snap)
        alerts.extend(anomaly_alerts)

        self._snapshots.append(snap)
        self._append(snap)

        for a in alerts:
            level = logger.error if a.blocking else logger.warning
            level(str(a))

        return alerts

    # ── Query ────────────────────────────────────────────────────────

    def latest(self) -> Optional[MetricSnapshot]:
        return self._snapshots[-1] if self._snapshots else None

    def history(self, n: int = 20) -> list[MetricSnapshot]:
        return list(self._snapshots[-n:])

    def metric_history(self, metric: str, n: int = 20) -> list[float]:
        """Return the last *n* values for a specific metric."""
        return [getattr(s, metric, 0.0) for s in self._snapshots[-n:]]

    def ema(self, metric: str, alpha: float = 0.3) -> float:
        """Exponential moving average for *metric* over all snapshots."""
        return _ema(self.metric_history(metric), alpha)

    def sma(self, metric: str, window: Optional[int] = None) -> float:
        """Simple moving average for *metric* over the last *window* snapshots."""
        return _sma(self.metric_history(metric), window or self._window)

    def slope(self, metric: str, window: Optional[int] = None) -> float:
        """Trend slope (positive = improving, negative = degrading) for *metric*."""
        return _linear_slope(self.metric_history(metric, n=window or self._window))

    def trend_report(self) -> dict:
        """Generate a comprehensive trend report suitable for CI artefacts."""
        metrics = ["tpr", "fpr", "f1", "bypass_rate", "mcc"]
        report: dict = {
            "snapshots_total": len(self._snapshots),
            "latest_session": self.latest().session_id if self.latest() else None,
        }
        for m in metrics:
            hist = self.metric_history(m, n=self._window)
            report[m] = {
                "latest": hist[-1] if hist else None,
                "sma": round(_sma(hist), 6),
                "ema": round(_ema(hist), 6),
                "slope": round(_linear_slope(hist), 8),
                "min": round(min(hist), 6) if hist else None,
                "max": round(max(hist), 6) if hist else None,
            }
        return report

    def render_text_report(self) -> str:
        """Render a human-readable trend summary."""
        rpt = self.trend_report()
        lines = [
            "┌─────────────────────────────────────────────┐",
            "│          Sentinel Trend Report               │",
            f"│  Sessions tracked : {rpt['snapshots_total']:<24}│",
            f"│  Latest session   : {str(rpt['latest_session'])[:24]:<24}│",
            "├──────────┬──────────┬──────────┬────────────┤",
            "│ Metric   │  Latest  │   SMA    │   Slope    │",
            "├──────────┼──────────┼──────────┼────────────┤",
        ]
        for metric in ["tpr", "fpr", "f1", "bypass_rate", "mcc"]:
            m = rpt.get(metric, {})
            latest = f"{m['latest']:.4f}" if m.get("latest") is not None else "N/A"
            sma = f"{m['sma']:.4f}" if m.get("sma") is not None else "N/A"
            slope = f"{m['slope']:+.6f}" if m.get("slope") is not None else "N/A"
            lines.append(f"│ {metric:<8} │ {latest:<8} │ {sma:<8} │ {slope:<10} │")
        lines.append("└──────────┴──────────┴──────────┴────────────┘")
        return "\n".join(lines)

    # ── Internal ──────────────────────────────────────────────────────

    def _check_threshold_alerts(self, current: MetricSnapshot) -> list[TrendAlert]:
        prev = self._snapshots[-1]
        alerts = []
        checks = [
            ("tpr", prev.tpr, current.tpr, "drop", lambda d: d < 0),
            ("fpr", prev.fpr, current.fpr, "spike", lambda d: d > 0),
            ("f1", prev.f1, current.f1, "drop", lambda d: d < 0),
            ("bypass_rate", prev.bypass_rate, current.bypass_rate, "spike", lambda d: d > 0),
            ("mcc", prev.mcc, current.mcc, "drop", lambda d: d < 0),
        ]
        for metric, p, c, direction, is_bad in checks:
            delta = c - p
            threshold = self._thresholds.get(metric, 0.02)
            if is_bad(delta) and abs(delta) >= threshold:
                alerts.append(TrendAlert(
                    metric=metric,
                    previous=round(p, 6),
                    current=round(c, 6),
                    delta=round(delta, 6),
                    threshold=threshold,
                    direction=direction,
                    session_id=current.session_id,
                    blocking=metric in self._blocking,
                ))
        return alerts

    def _check_anomaly_alerts(self, current: MetricSnapshot) -> list[TrendAlert]:
        """Detect anomalies using Z-score on recent metric history."""
        if len(self._snapshots) < 5:
            return []
        alerts = []
        anomaly_checks = [
            ("tpr", current.tpr, "drop"),
            ("f1", current.f1, "drop"),
            ("bypass_rate", current.bypass_rate, "spike"),
        ]
        for metric, value, direction in anomaly_checks:
            hist = self.metric_history(metric, n=self._window)
            if len(hist) < 3:
                continue
            z = _zscore(value, hist)
            is_bad = (direction == "drop" and z < -self._zscore_alert) or \
                     (direction == "spike" and z > self._zscore_alert)
            if is_bad:
                prev = hist[-1] if hist else 0.0
                delta = value - prev
                threshold = self._thresholds.get(metric, 0.02)
                alerts.append(TrendAlert(
                    metric=metric,
                    previous=round(prev, 6),
                    current=round(value, 6),
                    delta=round(delta, 6),
                    threshold=threshold,
                    direction=f"anomaly-{direction}(z={z:.2f})",
                    session_id=current.session_id,
                    blocking=metric in self._blocking and abs(z) > self._zscore_alert * 1.5,
                ))
        return alerts

    def _load(self) -> None:
        if not self._path.exists():
            return
        for line in self._path.read_text(encoding="utf-8").splitlines():
            line = line.strip()
            if not line:
                continue
            try:
                d = json.loads(line)
                self._snapshots.append(MetricSnapshot.from_dict(d))
            except Exception as exc:
                logger.warning("Malformed trend JSONL line: %s", exc)

    def _append(self, snap: MetricSnapshot) -> None:
        with self._path.open("a", encoding="utf-8") as fh:
            fh.write(json.dumps(snap.to_dict()) + "\n")

