"""Adaptive RL-based strategy selector — epsilon-greedy multi-armed bandit.

Maintains per-strategy success rates across the lifetime of the strategy
instance (session-scoped) and selects from the top-k strategies using
an epsilon-greedy policy.

Success is updated externally via :meth:`record_outcome`; the orchestrator
should call this after each probe attempt with ``success=True/False``.
"""
from __future__ import annotations

import logging
import random
from collections import defaultdict
from typing import Any

from sentinel.redteam.strategies.base import BaseStrategy, StrategyRegistry

logger = logging.getLogger(__name__)


class AdaptiveStrategy(BaseStrategy):
    """Epsilon-greedy bandit that selects from the full strategy registry.

    Each call to :meth:`transform` selects ``top_k`` strategies (by estimated
    success rate), applies them all to the prompt, and returns the combined
    variants.

    Attributes:
        epsilon: Exploration probability (0.0 = greedy, 1.0 = random).
        top_k:   Number of strategies to combine per transform call.
    """

    name = "adaptive"
    description = (
        "Epsilon-greedy RL bandit that combines the best-performing strategies "
        "from the registry based on observed success rates."
    )

    epsilon: float = 0.15
    top_k: int = 4

    def __init__(self) -> None:
        # success_counts[strategy_name] = (wins, total)
        self._wins: dict[str, int] = defaultdict(int)
        self._trials: dict[str, int] = defaultdict(int)
        self._strategies: dict[str, BaseStrategy] | None = None

    # ── Registry bootstrap ────────────────────────────────────────────

    def _get_strategies(self) -> dict[str, BaseStrategy]:
        if self._strategies is None:
            StrategyRegistry.discover()
            registry = StrategyRegistry.all_strategies()
            self._strategies = {}
            for name, cls in registry.items():
                if name in ("adaptive", "base"):
                    continue
                try:
                    self._strategies[name] = cls()
                except Exception as exc:
                    logger.debug("Skipping strategy %s: %s", name, exc)
        return self._strategies

    # ── Bandit logic ──────────────────────────────────────────────────

    def _ucb_score(self, name: str) -> float:
        """Upper Confidence Bound score for strategy selection."""
        wins = self._wins[name]
        trials = self._trials[name]
        if trials == 0:
            return 1.0  # Unvisited → maximum optimism
        return wins / trials

    def _select_strategies(self, available: list[str]) -> list[str]:
        k = min(self.top_k, len(available))
        if random.random() < self.epsilon:
            # Explore: pick k random strategies
            return random.sample(available, k)
        # Exploit: top-k by UCB score
        ranked = sorted(available, key=self._ucb_score, reverse=True)
        return ranked[:k]

    # ── Public API ────────────────────────────────────────────────────

    def record_outcome(self, strategy_name: str, success: bool) -> None:
        """Update bandit statistics after a probe attempt."""
        self._trials[strategy_name] += 1
        if success:
            self._wins[strategy_name] += 1

    def strategy_stats(self) -> dict[str, dict[str, Any]]:
        """Return current per-strategy statistics."""
        strats = self._get_strategies()
        return {
            name: {
                "wins": self._wins[name],
                "trials": self._trials[name],
                "rate": self._wins[name] / self._trials[name] if self._trials[name] else 0.0,
            }
            for name in strats
        }

    # ── BaseStrategy interface ────────────────────────────────────────

    def transform(self, prompt: str) -> list[str]:
        strats = self._get_strategies()
        if not strats:
            return [prompt]

        selected_names = self._select_strategies(list(strats.keys()))
        variants: list[str] = []

        for name in selected_names:
            strategy = strats[name]
            try:
                results = strategy.transform(prompt)
                variants.extend(results)
                # Optimistically count as trial; outcome should be updated later
                self._trials[name] += 1
            except Exception as exc:
                logger.debug("Strategy %s failed during transform: %s", name, exc)

        # Deduplicate while preserving order
        seen: set[str] = set()
        unique: list[str] = []
        for v in variants:
            if v not in seen:
                seen.add(v)
                unique.append(v)

        return unique or [prompt]
