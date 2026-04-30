"""Trace-level assertions: span count, duration, and ordering checks."""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sentinel.redteam.assertion_registry import AssertionResult, AssertionStatus


@dataclass
class TraceSpan:
    name: str
    duration_ms: float
    start_ms: float = 0.0
    attributes: dict[str, Any] = field(default_factory=dict)
    children: list[TraceSpan] = field(default_factory=list)


@dataclass
class Trace:
    trace_id: str
    spans: list[TraceSpan] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def total_duration_ms(self) -> float:
        if not self.spans:
            return 0.0
        end = max(s.start_ms + s.duration_ms for s in self.spans)
        start = min(s.start_ms for s in self.spans)
        return end - start

    @property
    def span_count(self) -> int:
        return len(self.spans)


def assert_span_count(
    trace: Trace, expected_min: int, expected_max: int | None = None,
) -> AssertionResult:
    count = trace.span_count
    if expected_max is not None:
        ok = expected_min <= count <= expected_max
        msg = f"Span count {count} in [{expected_min}, {expected_max}]"
    else:
        ok = count >= expected_min
        msg = f"Span count {count} >= {expected_min}"
    return AssertionResult(
        assertion_id="trace-span-count",
        status=AssertionStatus.PASS if ok else AssertionStatus.FAIL,
        message=msg,
        actual=count,
        expected=f"{expected_min}-{expected_max}" if expected_max else f">={expected_min}",
    )


def assert_max_duration(trace: Trace, max_ms: float) -> AssertionResult:
    total = trace.total_duration_ms
    ok = total <= max_ms
    return AssertionResult(
        assertion_id="trace-max-duration",
        status=AssertionStatus.PASS if ok else AssertionStatus.FAIL,
        message=f"Total duration {total:.1f}ms {'<=' if ok else '>'} {max_ms}ms",
        actual=total,
        expected=max_ms,
    )


def assert_span_order(trace: Trace, expected_order: list[str]) -> AssertionResult:
    span_names = [s.name for s in sorted(trace.spans, key=lambda s: s.start_ms)]
    found_order = [n for n in span_names if n in expected_order]
    ok = found_order == expected_order
    return AssertionResult(
        assertion_id="trace-span-order",
        status=AssertionStatus.PASS if ok else AssertionStatus.FAIL,
        message=f"Span order: expected {expected_order}, found {found_order}",
        actual=found_order,
        expected=expected_order,
    )


def assert_no_long_spans(trace: Trace, threshold_ms: float) -> AssertionResult:
    long_spans = [s for s in trace.spans if s.duration_ms > threshold_ms]
    ok = len(long_spans) == 0
    return AssertionResult(
        assertion_id="trace-no-long-spans",
        status=AssertionStatus.PASS if ok else AssertionStatus.FAIL,
        message=f"{len(long_spans)} spans exceed {threshold_ms}ms threshold",
        actual=[s.name for s in long_spans],
        expected="no spans exceeding threshold",
    )
