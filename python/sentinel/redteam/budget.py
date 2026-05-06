"""Budget Controller — API cost and token limiter for red-team runs.

Wraps any Generator and tracks cumulative cost and token usage.
Raises BudgetExceededError when configured limits are hit, preventing
runaway API bills during large-scale red-team exercises.

Usage::

    from sentinel.redteam.budget import BudgetController
    from sentinel.redteam.generators.openai import OpenAIGenerator

    gen = OpenAIGenerator(model="gpt-4o")
    budget_gen = BudgetController(gen, max_cost_usd=1.00, max_tokens=50_000)

    try:
        response = budget_gen.generate("What is SQL injection?")
    except BudgetExceededError as e:
        print(f"Budget hit: {e}")
"""
from __future__ import annotations

import logging
import threading
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


class BudgetExceededError(RuntimeError):
    """Raised when a budget limit (cost or tokens) is exceeded."""

    def __init__(self, message: str, spent: float, limit: float, unit: str) -> None:
        super().__init__(message)
        self.spent = spent
        self.limit = limit
        self.unit = unit


@dataclass
class BudgetSnapshot:
    """Point-in-time usage snapshot."""
    total_cost_usd: float = 0.0
    total_tokens: int = 0
    total_requests: int = 0
    cost_limit_usd: float | None = None
    token_limit: int | None = None
    cost_remaining_usd: float | None = None
    token_remaining: int | None = None
    within_budget: bool = True

    @property
    def cost_pct(self) -> float | None:
        if self.cost_limit_usd and self.cost_limit_usd > 0:
            return round(self.total_cost_usd / self.cost_limit_usd * 100, 1)
        return None

    @property
    def token_pct(self) -> float | None:
        if self.token_limit and self.token_limit > 0:
            return round(self.total_tokens / self.token_limit * 100, 1)
        return None


class BudgetController:
    """Wraps a Generator with cost + token budget enforcement.

    Args:
        generator:       Any generator with a .generate(prompt) method.
        max_cost_usd:    Hard stop when cumulative cost exceeds this (USD).
        max_tokens:      Hard stop when cumulative tokens exceed this.
        max_requests:    Hard stop after this many API calls.
        warn_at_pct:     Log a warning when budget reaches this percentage (0-100).
        on_budget_warn:  Optional callback(snapshot) called on warning.
    """

    def __init__(
        self,
        generator: Any,
        max_cost_usd: float | None = None,
        max_tokens: int | None = None,
        max_requests: int | None = None,
        warn_at_pct: float = 80.0,
        on_budget_warn: Any | None = None,
    ) -> None:
        self._gen = generator
        self._max_cost = max_cost_usd
        self._max_tokens = max_tokens
        self._max_requests = max_requests
        self._warn_pct = warn_at_pct / 100.0
        self._on_warn = on_budget_warn
        self._lock = threading.Lock()

        self._total_cost: float = 0.0
        self._total_tokens: int = 0
        self._total_requests: int = 0
        self._warned: bool = False

    def _check_limits(self) -> None:
        """Raise BudgetExceededError if any limit is exceeded."""
        if self._max_cost and self._total_cost >= self._max_cost:
            raise BudgetExceededError(
                f"API cost budget exceeded: ${self._total_cost:.4f} >= ${self._max_cost:.4f}",
                spent=self._total_cost,
                limit=self._max_cost,
                unit="USD",
            )
        if self._max_tokens and self._total_tokens >= self._max_tokens:
            raise BudgetExceededError(
                f"Token budget exceeded: {self._total_tokens:,} >= {self._max_tokens:,} tokens",
                spent=float(self._total_tokens),
                limit=float(self._max_tokens),
                unit="tokens",
            )
        if self._max_requests and self._total_requests >= self._max_requests:
            raise BudgetExceededError(
                f"Request budget exceeded: {self._total_requests} >= {self._max_requests} requests",
                spent=float(self._total_requests),
                limit=float(self._max_requests),
                unit="requests",
            )

    def _maybe_warn(self) -> None:
        if self._warned:
            return
        cost_pct = self._total_cost / self._max_cost if self._max_cost else 0
        token_pct = self._total_tokens / self._max_tokens if self._max_tokens else 0
        req_pct = self._total_requests / self._max_requests if self._max_requests else 0

        if max(cost_pct, token_pct, req_pct) >= self._warn_pct:
            self._warned = True
            snap = self.snapshot()
            logger.warning(
                "Budget warning: %s%% cost ($%.4f/$%.4f), %s%% tokens (%d/%s)",
                snap.cost_pct or "N/A", self._total_cost, self._max_cost or 0,
                snap.token_pct or "N/A", self._total_tokens, str(self._max_tokens) or "∞",
            )
            if self._on_warn:
                try:
                    self._on_warn(snap)
                except Exception:
                    pass

    def generate(self, prompt: str, **kwargs) -> Any:
        """Generate with budget enforcement."""
        with self._lock:
            self._check_limits()

        response = self._gen.generate(prompt, **kwargs)

        with self._lock:
            self._total_requests += 1
            tokens = getattr(response, "total_tokens", 0) or 0
            self._total_tokens += tokens
            cost = getattr(response, "estimated_cost_usd", 0.0) or 0.0
            self._total_cost += cost
            self._maybe_warn()

        return response

    def chat(self, messages: list[dict], **kwargs) -> Any:
        """Chat with budget enforcement."""
        with self._lock:
            self._check_limits()

        response = self._gen.chat(messages, **kwargs)

        with self._lock:
            self._total_requests += 1
            tokens = getattr(response, "total_tokens", 0) or 0
            self._total_tokens += tokens
            cost = getattr(response, "estimated_cost_usd", 0.0) or 0.0
            self._total_cost += cost
            self._maybe_warn()

        return response

    def snapshot(self) -> BudgetSnapshot:
        """Return current usage snapshot."""
        with self._lock:
            remaining_cost = (self._max_cost - self._total_cost) if self._max_cost else None
            remaining_tok = (self._max_tokens - self._total_tokens) if self._max_tokens else None
            return BudgetSnapshot(
                total_cost_usd=round(self._total_cost, 6),
                total_tokens=self._total_tokens,
                total_requests=self._total_requests,
                cost_limit_usd=self._max_cost,
                token_limit=self._max_tokens,
                cost_remaining_usd=round(remaining_cost, 6) if remaining_cost is not None else None,
                token_remaining=remaining_tok,
                within_budget=True,
            )

    def reset(self) -> None:
        """Reset all counters."""
        with self._lock:
            self._total_cost = 0.0
            self._total_tokens = 0
            self._total_requests = 0
            self._warned = False

    def __getattr__(self, name: str) -> Any:
        """Proxy unknown attributes to the wrapped generator."""
        return getattr(self._gen, name)

    def __repr__(self) -> str:
        snap = self.snapshot()
        return (
            f"BudgetController(generator={self._gen!r}, "
            f"spent=${snap.total_cost_usd:.4f}/{self._max_cost or '∞'}, "
            f"tokens={snap.total_tokens:,}/{self._max_tokens or '∞'})"
        )
