"""
Eresus Sentinel — Cost Guard Scanner (Input)

Estimates per-prompt token cost and enforces budget limits to prevent
cost overruns from large or complex prompts.

Features:
  - Token-based cost estimation (simple heuristic)
  - Per-request cost limits
  - Per-minute cost accumulation
  - Daily budget tracking
  - Configurable token-to-cost ratios per model
  - Output token estimation multiplier

Token/cost estimation for LLM requests.
"""

from __future__ import annotations

import logging
import time
from typing import Optional

from sentinel.finding import Finding, Severity
from sentinel.firewall.base import InputScanner, ScanResult, ScanAction

logger = logging.getLogger(__name__)

# Approximate pricing per 1K tokens (USD) — conservative estimates
MODEL_PRICING = {
    "gpt-4o": {"input": 0.005, "output": 0.015},
    "gpt-4-turbo": {"input": 0.01, "output": 0.03},
    "gpt-4": {"input": 0.03, "output": 0.06},
    "gpt-3.5-turbo": {"input": 0.0005, "output": 0.0015},
    "claude-3-opus": {"input": 0.015, "output": 0.075},
    "claude-3-sonnet": {"input": 0.003, "output": 0.015},
    "claude-3-haiku": {"input": 0.00025, "output": 0.00125},
    "gemini-pro": {"input": 0.00025, "output": 0.0005},
    "llama-3-70b": {"input": 0.00059, "output": 0.00079},
    "default": {"input": 0.005, "output": 0.015},
}


class CostGuardScanner(InputScanner):
    """Estimates per-prompt cost and enforces budget limits."""

    def __init__(
        self,
        max_cost_per_request: float = 0.50,
        max_cost_per_minute: float = 5.00,
        daily_budget: float = 100.00,
        model: str = "default",
        estimate_output_ratio: float = 2.0,
    ):
        self._max_per_request = max_cost_per_request
        self._max_per_minute = max_cost_per_minute
        self._daily_budget = daily_budget
        self._pricing = MODEL_PRICING.get(model, MODEL_PRICING["default"])
        self._output_ratio = estimate_output_ratio
        self._minute_costs: list[tuple[float, float]] = []
        self._daily_total: float = 0.0
        self._daily_reset: float = time.monotonic()

    def _estimate_tokens(self, text: str) -> int:
        return max(1, len(text) // 4)

    def _estimate_cost(self, input_tokens: int) -> float:
        output_tokens = int(input_tokens * self._output_ratio)
        input_cost = (input_tokens / 1000) * self._pricing["input"]
        output_cost = (output_tokens / 1000) * self._pricing["output"]
        return input_cost + output_cost

    def scan(self, prompt: str) -> ScanResult:
        if not prompt.strip():
            return ScanResult(sanitized=prompt, action=ScanAction.PASS, risk_score=0.0)

        now = time.monotonic()
        input_tokens = self._estimate_tokens(prompt)
        estimated_cost = self._estimate_cost(input_tokens)

        # Reset daily budget
        if now - self._daily_reset >= 86400:
            self._daily_total = 0.0
            self._daily_reset = now

        # Prune minute window
        self._minute_costs = [(t, c) for t, c in self._minute_costs if now - t < 60]

        findings = []
        risk = 0.0

        # Per-request check
        if estimated_cost > self._max_per_request:
            risk = 0.9
            findings.append(Finding.firewall_input(
                rule_id="FIREWALL-INPUT-090",
                title="Estimated request cost exceeds limit",
                description=(
                    f"Request estimated at ${estimated_cost:.4f} "
                    f"(limit: ${self._max_per_request:.2f}). "
                    f"Input tokens: ~{input_tokens}"
                ),
                severity=Severity.HIGH,
                target="<prompt>",
                evidence=f"Cost: ${estimated_cost:.4f}, Tokens: {input_tokens}",
                cwe_ids=["CWE-400"],
                tags=["cost_guard", "budget"],
            ))

        # Per-minute check
        minute_total = sum(c for _, c in self._minute_costs) + estimated_cost
        if minute_total > self._max_per_minute:
            risk = max(risk, 0.8)
            findings.append(Finding.firewall_input(
                rule_id="FIREWALL-INPUT-091",
                title="Per-minute cost budget exceeded",
                description=f"Minute spend: ${minute_total:.4f} (limit: ${self._max_per_minute:.2f})",
                severity=Severity.HIGH,
                target="<request>",
                evidence=f"Minute total: ${minute_total:.4f}",
                cwe_ids=["CWE-400"],
                tags=["cost_guard", "budget"],
            ))

        # Daily budget check
        if self._daily_total + estimated_cost > self._daily_budget:
            risk = max(risk, 1.0)
            findings.append(Finding.firewall_input(
                rule_id="FIREWALL-INPUT-092",
                title="Daily cost budget exhausted",
                description=f"Daily spend: ${self._daily_total:.2f} + ${estimated_cost:.4f} > ${self._daily_budget:.2f}",
                severity=Severity.CRITICAL,
                target="<request>",
                evidence=f"Daily: ${self._daily_total:.2f}/{self._daily_budget:.2f}",
                cwe_ids=["CWE-400"],
                tags=["cost_guard", "budget", "daily"],
            ))

        # Track costs (even if blocked, for monitoring)
        self._minute_costs.append((now, estimated_cost))
        self._daily_total += estimated_cost

        if not findings:
            return ScanResult(
                sanitized=prompt,
                action=ScanAction.PASS,
                risk_score=0.0,
                metadata={"estimated_cost": estimated_cost, "input_tokens": input_tokens},
            )

        action = ScanAction.BLOCK if risk >= 1.0 else ScanAction.WARN
        return ScanResult(
            sanitized=prompt,
            action=action,
            risk_score=risk,
            findings=findings,
            metadata={"estimated_cost": estimated_cost, "input_tokens": input_tokens},
        )

    def get_usage(self) -> dict:
        return {
            "daily_total": round(self._daily_total, 4),
            "daily_budget": self._daily_budget,
            "daily_remaining": round(self._daily_budget - self._daily_total, 4),
        }
