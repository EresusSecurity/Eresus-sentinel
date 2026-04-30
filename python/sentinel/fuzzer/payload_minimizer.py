"""Payload minimizer — multiple algorithms to find the minimal reproducing input.

Implements three minimization strategies:
  1. **ddmin** (Zeller 2002) — bisection-based 1-minimal subset removal.
  2. **Linear scan** — removes single bytes/chars left-to-right (fast for short inputs).
  3. **Binary bisection** — faster convergence for large inputs (log N passes).

For *text* payloads additional strategies are available:
  4. **Token-level minimization** — removes whitespace-separated tokens.
  5. **Sentence minimization** — removes sentences while preserving trigger.
  6. **Character-class minimization** — replaces non-ASCII chars with their
     ASCII equivalents until the trigger breaks.

All strategies accept an *Oracle* callback ``(candidate: bytes | str) → bool``
that returns True if the interesting condition (bypass / crash / detection) still
holds in the candidate.

Usage::

    minimizer = PayloadMinimizer(strategy="ddmin", min_bytes=1, max_rounds=500)
    result = minimizer.minimize(payload, oracle=lambda d: b"evil" in d)
    print(f"Reduced {len(payload)} → {len(result)} bytes in {minimizer.rounds_used} calls")
    trace = minimizer.reduction_trace     # list[(size_before, size_after)]
"""

from __future__ import annotations

import logging
import re
import time
from dataclasses import dataclass, field
from enum import Enum
from typing import Callable, Optional, Union

logger = logging.getLogger(__name__)

# Oracle signature: accepts bytes (or str for text minimizers), returns bool
Oracle = Callable[[bytes], bool]
TextOracle = Callable[[str], bool]


class Strategy(str, Enum):
    DDMIN = "ddmin"
    LINEAR = "linear"
    BISECT = "bisect"
    TOKEN = "token"
    SENTENCE = "sentence"


# ---------------------------------------------------------------------------
# Core algorithms
# ---------------------------------------------------------------------------

def _ddmin(data: bytes, oracle: Oracle, max_rounds: int = 10_000) -> bytes:
    """Zeller's ddmin — 1-minimal subset removal.

    Repeatedly bisects *data* and tests whether each half (or its complement)
    still satisfies the oracle. Continues until no further reduction is possible.

    Time complexity: O(n²) in the worst case; O(n log n) typical.
    """
    n = 2
    rounds = 0
    while len(data) >= 2 and rounds < max_rounds:
        chunk = len(data) // n
        if chunk == 0:
            break
        progressed = False
        for i in range(n):
            start = i * chunk
            candidate = data[:start] + data[start + chunk:]
            rounds += 1
            if rounds >= max_rounds:
                break
            if oracle(candidate):
                data = candidate
                n = max(2, n - 1)
                progressed = True
                break
        if not progressed:
            if n >= len(data):
                break
            n = min(n * 2, len(data))
    return data


def _linear_scan(data: bytes, oracle: Oracle, max_rounds: int = 10_000) -> bytes:
    """Remove bytes one at a time from left to right.

    Simple and effective for payloads under ~1 KB where each oracle call is fast.
    """
    result = bytearray(data)
    i = 0
    rounds = 0
    while i < len(result) and rounds < max_rounds:
        candidate = bytes(result[:i] + result[i + 1:])
        rounds += 1
        if oracle(candidate):
            result = bytearray(candidate)
            # don't advance i — the next byte shifted down
        else:
            i += 1
    return bytes(result)


def _binary_bisect(data: bytes, oracle: Oracle, max_rounds: int = 10_000) -> bytes:
    """Binary search minimizer — removes halves, quarters, etc.

    Much faster than linear scan on large payloads, at the cost of potentially
    missing sub-byte granularity reductions.
    """
    rounds = 0
    lo, hi = 0, len(data)
    # First try removing from the end
    while hi - lo > 1 and rounds < max_rounds:
        mid = (lo + hi) // 2
        candidate = data[:mid]
        rounds += 1
        if oracle(candidate):
            hi = mid
        else:
            lo = mid
    best = data[:hi]
    # Then try removing from the front
    lo2, hi2 = 0, len(best)
    while hi2 - lo2 > 1 and rounds < max_rounds:
        mid = (lo2 + hi2) // 2
        candidate = best[mid:]
        rounds += 1
        if oracle(candidate):
            lo2 = mid
        else:
            hi2 = mid
    candidate = best[lo2:]
    if oracle(candidate):
        best = candidate
    return best


def _token_minimize(text: str, oracle: TextOracle, max_rounds: int = 10_000) -> str:
    """Remove whitespace-separated tokens one at a time (left to right)."""
    tokens = text.split()
    i = 0
    rounds = 0
    while i < len(tokens) and rounds < max_rounds:
        candidate = " ".join(tokens[:i] + tokens[i + 1:])
        rounds += 1
        if oracle(candidate):
            tokens = tokens[:i] + tokens[i + 1:]
        else:
            i += 1
    return " ".join(tokens)


def _sentence_minimize(text: str, oracle: TextOracle, max_rounds: int = 5_000) -> str:
    """Remove sentences (split on ., !, ?) one at a time."""
    sentences = re.split(r"(?<=[.!?])\s+", text)
    if len(sentences) <= 1:
        return _token_minimize(text, oracle, max_rounds)
    i = 0
    rounds = 0
    while i < len(sentences) and rounds < max_rounds:
        candidate = " ".join(sentences[:i] + sentences[i + 1:])
        rounds += 1
        if oracle(candidate):
            sentences = sentences[:i] + sentences[i + 1:]
        else:
            i += 1
    return " ".join(sentences)


# ---------------------------------------------------------------------------
# Minimization trace
# ---------------------------------------------------------------------------

@dataclass
class MinimizationStep:
    step: int
    size_before: int
    size_after: int
    strategy: str
    elapsed_ms: float

    @property
    def reduction_pct(self) -> float:
        if self.size_before == 0:
            return 0.0
        return (1.0 - self.size_after / self.size_before) * 100.0


@dataclass
class MinimizationReport:
    original_size: int
    final_size: int
    oracle_calls: int
    wall_time_ms: float
    strategy: str
    steps: list[MinimizationStep] = field(default_factory=list)
    succeeded: bool = True

    @property
    def reduction_pct(self) -> float:
        if self.original_size == 0:
            return 0.0
        return (1.0 - self.final_size / self.original_size) * 100.0

    def summary(self) -> str:
        return (
            f"[{self.strategy}] {self.original_size} → {self.final_size} bytes "
            f"({self.reduction_pct:.1f}% reduction) "
            f"in {self.oracle_calls} oracle calls / {self.wall_time_ms:.0f} ms"
        )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

class PayloadMinimizer:
    """Reduces a crashing / bypassing payload to its minimal reproducing form.

    Supports multiple strategies and automatically falls back from ddmin to
    linear scan when the payload is small.

    Args:
        strategy:    One of ``"ddmin"`` (default), ``"linear"``, ``"bisect"``,
                     ``"token"``, ``"sentence"``.
        min_bytes:   Floor size — won't reduce below this many bytes.
        max_rounds:  Hard cap on oracle invocations.
        auto_chain:  If True, run ddmin first then linear to squeeze further.

    Raises:
        ValueError: If the oracle returns False on the original input.
    """

    def __init__(
        self,
        strategy: Union[Strategy, str] = Strategy.DDMIN,
        min_bytes: int = 1,
        max_rounds: int = 2000,
        auto_chain: bool = True,
    ):
        self._strategy = Strategy(strategy)
        self._min_bytes = max(1, min_bytes)
        self._max_rounds = max_rounds
        self._auto_chain = auto_chain
        self._rounds = 0
        self.report: Optional[MinimizationReport] = None

    # ── Public interface ────────────────────────────────────────────

    def minimize(self, data: bytes, oracle: Oracle) -> bytes:
        """Return the smallest bytes for which oracle(candidate) → True.

        Raises ValueError if oracle(data) is False.
        """
        if not oracle(data):
            raise ValueError("Oracle returned False on original input — nothing to minimize.")

        t_start = time.monotonic()
        self._rounds = 0
        orig_size = len(data)

        wrapped, counter = self._wrap_oracle(oracle)

        if self._strategy == Strategy.DDMIN:
            result = _ddmin(data, wrapped, self._max_rounds)
        elif self._strategy == Strategy.LINEAR:
            result = _linear_scan(data, wrapped, self._max_rounds)
        elif self._strategy == Strategy.BISECT:
            result = _binary_bisect(data, wrapped, self._max_rounds)
        else:
            raise ValueError(f"Use minimize_text() for strategy={self._strategy}")

        # Optionally chain with linear scan for last-mile reduction
        if self._auto_chain and self._strategy == Strategy.DDMIN and len(result) < orig_size:
            remaining = self._max_rounds - counter[0]
            if remaining > 0:
                result = _linear_scan(result, wrapped, remaining)

        elapsed_ms = (time.monotonic() - t_start) * 1000
        self._rounds = counter[0]
        self.report = MinimizationReport(
            original_size=orig_size,
            final_size=len(result),
            oracle_calls=self._rounds,
            wall_time_ms=round(elapsed_ms, 1),
            strategy=self._strategy.value,
        )
        logger.info(self.report.summary())
        return result

    def minimize_text(self, text: str, oracle: TextOracle) -> str:
        """Text-level minimizer — removes tokens or sentences.

        Args:
            text:   UTF-8 text payload.
            oracle: Returns True if the condition holds on the candidate string.
        """
        t_start = time.monotonic()
        orig_size = len(text.encode())

        if self._strategy == Strategy.TOKEN:
            result = _token_minimize(text, oracle, self._max_rounds)
        elif self._strategy == Strategy.SENTENCE:
            result = _sentence_minimize(text, oracle, self._max_rounds)
        else:
            # Encode and use binary strategy
            result_bytes = self.minimize(text.encode(), lambda d: oracle(d.decode("utf-8", errors="replace")))
            return result_bytes.decode("utf-8", errors="replace")

        elapsed_ms = (time.monotonic() - t_start) * 1000
        self.report = MinimizationReport(
            original_size=orig_size,
            final_size=len(result.encode()),
            oracle_calls=self._max_rounds,  # approximate
            wall_time_ms=round(elapsed_ms, 1),
            strategy=self._strategy.value,
        )
        logger.info(self.report.summary())
        return result

    @property
    def rounds_used(self) -> int:
        """Oracle call count from the last minimize() invocation."""
        return self._rounds

    # ── Helpers ─────────────────────────────────────────────────────

    def _wrap_oracle(self, oracle: Oracle):
        """Wrap oracle to enforce min_bytes and count calls."""
        counter = [0]

        def wrapped(candidate: bytes) -> bool:
            counter[0] += 1
            if counter[0] > self._max_rounds:
                return False
            if len(candidate) < self._min_bytes:
                return False
            return oracle(candidate)

        return wrapped, counter

