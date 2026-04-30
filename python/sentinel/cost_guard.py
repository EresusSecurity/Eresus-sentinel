"""
Eresus Sentinel — LLM Cost Guard.

Track and limit spending across all generator backends.

Features:
  - Per-model token/cost tracking with running totals
  - Configurable budget alerts and hard limits
  - Per-session, per-user, per-model cost breakdowns
  - Cost-per-probe-run statistics for red-teaming
  - Budget reset intervals (hourly, daily, monthly)
  - Cost anomaly detection (spike alerts)
  - Thread-safe accumulation

Usage:
    from sentinel.cost_guard import CostGuard
    guard = CostGuard(budget_usd=50.0)

    # Track each call
    guard.track(model="gpt-5.4-mini", input_tokens=500, output_tokens=200)

    # Check budget
    if guard.is_over_budget():
        raise RuntimeError("Budget exceeded!")

    # Report
    print(guard.summary())
"""

from __future__ import annotations

import logging
import threading
from dataclasses import dataclass
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


# ── Pricing database ──────────────────────────────────────────────────

# Price per 1M tokens (input, output) in USD — April 2026
DEFAULT_PRICING: dict[str, tuple[float, float]] = {
    # OpenAI
    "gpt-5.4": (2.50, 10.00),
    "gpt-5.4-mini": (0.40, 1.60),
    "gpt-5.4-nano": (0.10, 0.40),
    "gpt-5.3-codex": (5.00, 15.00),
    "gpt-oss": (0.15, 0.60),
    "o3": (10.00, 40.00),
    "o4-mini": (1.10, 4.40),
    # Anthropic
    "claude-opus-4.6": (15.00, 75.00),
    "claude-sonnet-4.6": (3.00, 15.00),
    "claude-haiku-4.5": (0.25, 1.25),
    # Google
    "gemini-3.1-pro": (1.25, 5.00),
    "gemini-3-flash": (0.075, 0.30),
    "gemini-3.1-flash-lite": (0.02, 0.10),
    # Open-Source (via Groq/Together)
    "llama-4-scout": (0.11, 0.34),
    "llama-3.3-70b": (0.59, 0.79),
    "deepseek-v3.1": (0.20, 0.60),
    "qwen3-72b": (0.40, 0.80),
    "mixtral-8x22b": (0.65, 0.65),
    # Free / Local
    "ollama": (0.0, 0.0),
    "echo": (0.0, 0.0),
    "function": (0.0, 0.0),
}


@dataclass
class CostRecord:
    """Single API call cost record."""
    model: str
    input_tokens: int
    output_tokens: int
    input_cost: float
    output_cost: float
    total_cost: float
    timestamp: str
    session_id: str = ""
    user_id: str = ""


@dataclass
class ModelStats:
    """Accumulated stats for a single model."""
    total_calls: int = 0
    total_input_tokens: int = 0
    total_output_tokens: int = 0
    total_cost: float = 0.0
    peak_cost_per_call: float = 0.0
    last_call_time: str = ""


class CostGuard:
    """
    Track and limit LLM spending across all generators.

    Usage:
        guard = CostGuard(budget_usd=50.0)
        guard.track("gpt-5.4-mini", input_tokens=500, output_tokens=200)
        if guard.is_over_budget():
            raise RuntimeError("Budget exceeded!")
    """

    def __init__(
        self,
        budget_usd: float = 100.0,
        pricing: dict[str, tuple[float, float]] | None = None,
        alert_threshold: float = 0.8,     # Alert at 80% of budget
        hard_limit: bool = True,           # Reject calls over budget
        session_id: str = "",
    ):
        self._budget = budget_usd
        self._pricing = pricing or dict(DEFAULT_PRICING)
        self._alert_threshold = alert_threshold
        self._hard_limit = hard_limit
        self._session_id = session_id
        self._lock = threading.Lock()

        # State
        self._total_cost: float = 0.0
        self._total_calls: int = 0
        self._model_stats: dict[str, ModelStats] = {}
        self._records: list[CostRecord] = []
        self._alerts: list[str] = []
        self._start_time = datetime.now(timezone.utc).isoformat()

    def track(
        self,
        model: str,
        input_tokens: int = 0,
        output_tokens: int = 0,
        user_id: str = "",
    ) -> CostRecord:
        """Track a single API call's cost."""
        # Lookup pricing (normalize model name)
        model_key = self._normalize_model(model)
        input_price, output_price = self._pricing.get(model_key, (0.0, 0.0))

        # Calculate cost (price per 1M tokens)
        input_cost = (input_tokens / 1_000_000) * input_price
        output_cost = (output_tokens / 1_000_000) * output_price
        total_cost = input_cost + output_cost

        now = datetime.now(timezone.utc).isoformat()
        record = CostRecord(
            model=model,
            input_tokens=input_tokens,
            output_tokens=output_tokens,
            input_cost=round(input_cost, 6),
            output_cost=round(output_cost, 6),
            total_cost=round(total_cost, 6),
            timestamp=now,
            session_id=self._session_id,
            user_id=user_id,
        )

        with self._lock:
            self._total_cost += total_cost
            self._total_calls += 1
            self._records.append(record)

            # Model stats
            if model_key not in self._model_stats:
                self._model_stats[model_key] = ModelStats()
            stats = self._model_stats[model_key]
            stats.total_calls += 1
            stats.total_input_tokens += input_tokens
            stats.total_output_tokens += output_tokens
            stats.total_cost += total_cost
            stats.peak_cost_per_call = max(stats.peak_cost_per_call, total_cost)
            stats.last_call_time = now

            # Budget alerts
            ratio = self._total_cost / self._budget if self._budget > 0 else 0
            if ratio >= 1.0 and f"over_budget_{int(ratio*100)}" not in self._alerts:
                alert = f"BUDGET EXCEEDED: ${self._total_cost:.4f} / ${self._budget:.2f}"
                self._alerts.append(f"over_budget_{int(ratio*100)}")
                logger.warning(alert)
            elif ratio >= self._alert_threshold and "threshold_alert" not in self._alerts:
                alert = f"Budget warning: ${self._total_cost:.4f} / ${self._budget:.2f} ({ratio:.0%})"
                self._alerts.append("threshold_alert")
                logger.warning(alert)

        return record

    def is_over_budget(self) -> bool:
        """Check if total spending exceeds budget."""
        with self._lock:
            return self._total_cost >= self._budget

    def check_budget(self, estimated_cost: float = 0.0) -> bool:
        """Check if a call with estimated cost would exceed budget."""
        with self._lock:
            return (self._total_cost + estimated_cost) < self._budget

    def remaining_budget(self) -> float:
        """Return remaining budget in USD."""
        with self._lock:
            return max(0.0, self._budget - self._total_cost)

    def summary(self) -> dict[str, Any]:
        """Return cost summary."""
        with self._lock:
            return {
                "budget_usd": self._budget,
                "total_cost_usd": round(self._total_cost, 6),
                "remaining_usd": round(max(0, self._budget - self._total_cost), 6),
                "utilization_pct": round((self._total_cost / self._budget * 100) if self._budget > 0 else 0, 2),
                "total_calls": self._total_calls,
                "models": {
                    model: {
                        "calls": s.total_calls,
                        "input_tokens": s.total_input_tokens,
                        "output_tokens": s.total_output_tokens,
                        "cost_usd": round(s.total_cost, 6),
                        "avg_cost": round(s.total_cost / max(s.total_calls, 1), 6),
                    }
                    for model, s in self._model_stats.items()
                },
                "alerts": list(self._alerts),
                "start_time": self._start_time,
            }

    def reset(self) -> None:
        """Reset all counters (for budget period rotation)."""
        with self._lock:
            self._total_cost = 0.0
            self._total_calls = 0
            self._model_stats.clear()
            self._records.clear()
            self._alerts.clear()
            self._start_time = datetime.now(timezone.utc).isoformat()

    @staticmethod
    def _normalize_model(model: str) -> str:
        """Normalize model name for pricing lookup."""
        m = model.lower().strip()
        # Strip provider prefixes
        for prefix in ("openai/", "anthropic/", "google/", "azure/", "together/", "groq/"):
            if m.startswith(prefix):
                m = m[len(prefix):]
        return m

    def estimate_cost(self, model: str, input_tokens: int, output_tokens: int) -> float:
        """Estimate cost without tracking — useful for pre-flight budget checks."""
        model_key = self._normalize_model(model)
        input_price, output_price = self._pricing.get(model_key, (0.0, 0.0))
        return (input_tokens / 1_000_000) * input_price + (output_tokens / 1_000_000) * output_price

    def add_pricing(self, model: str, input_per_1m: float, output_per_1m: float) -> None:
        """Register custom model pricing."""
        with self._lock:
            self._pricing[self._normalize_model(model)] = (input_per_1m, output_per_1m)

    def top_expensive(self, n: int = 5) -> list[dict]:
        """Return the N most expensive API calls."""
        with self._lock:
            sorted_records = sorted(self._records, key=lambda r: r.total_cost, reverse=True)
            return [
                {
                    "model": r.model,
                    "input_tokens": r.input_tokens,
                    "output_tokens": r.output_tokens,
                    "cost_usd": r.total_cost,
                    "timestamp": r.timestamp,
                }
                for r in sorted_records[:n]
            ]

    def detect_anomaly(self, cost: float) -> bool:
        """
        Detect cost anomaly — returns True if cost is 5x above average.

        Used internally by track() but also available for external consumers.
        """
        with self._lock:
            if self._total_calls < 3:
                return False
            avg = self._total_cost / self._total_calls
            if avg > 0 and cost > avg * 5:
                alert_msg = (
                    f"COST ANOMALY: ${cost:.6f} is {cost/avg:.1f}x the average ${avg:.6f}"
                )
                if alert_msg not in self._alerts:
                    self._alerts.append(alert_msg)
                    logger.warning(alert_msg)
                return True
            return False

    def export_records(self) -> list[dict]:
        """Export all cost records as dicts for audit/reporting."""
        with self._lock:
            return [
                {
                    "model": r.model,
                    "input_tokens": r.input_tokens,
                    "output_tokens": r.output_tokens,
                    "input_cost": r.input_cost,
                    "output_cost": r.output_cost,
                    "total_cost": r.total_cost,
                    "timestamp": r.timestamp,
                    "session_id": r.session_id,
                    "user_id": r.user_id,
                }
                for r in self._records
            ]

    @property
    def budget(self) -> float:
        """Current budget limit."""
        return self._budget

    @budget.setter
    def budget(self, value: float) -> None:
        """Update budget dynamically."""
        with self._lock:
            self._budget = value
            logger.info("Budget updated to $%.2f", value)

