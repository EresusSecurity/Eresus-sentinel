"""Score threshold gate for CI pipelines — determines exit code."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class GateConfig:
    min_pass_rate: float = 0.8
    max_critical_findings: int = 0
    max_high_findings: int = 5
    fail_on_error: bool = True
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class GateResult:
    passed: bool
    exit_code: int
    reasons: list[str] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)


def evaluate_gate(
    summary: dict[str, Any],
    config: GateConfig | None = None,
) -> GateResult:
    """Evaluate a scan/eval summary against gate thresholds."""
    cfg = config or GateConfig()
    reasons: list[str] = []

    total = summary.get("total", 0)
    passed_count = summary.get("passed", 0)
    pass_rate = passed_count / max(total, 1)

    if pass_rate < cfg.min_pass_rate:
        reasons.append(f"Pass rate {pass_rate:.0%} < threshold {cfg.min_pass_rate:.0%}")

    by_severity = summary.get("by_severity", {})
    critical = by_severity.get("CRITICAL", 0)
    high = by_severity.get("HIGH", 0)

    if critical > cfg.max_critical_findings:
        reasons.append(f"Critical findings {critical} > max {cfg.max_critical_findings}")

    if high > cfg.max_high_findings:
        reasons.append(f"High findings {high} > max {cfg.max_high_findings}")

    if cfg.fail_on_error and summary.get("errored", 0) > 0:
        reasons.append(f"Errors detected: {summary['errored']}")

    passed = len(reasons) == 0
    exit_code = 0 if passed else 1

    if critical > 0:
        exit_code = 2

    return GateResult(
        passed=passed,
        exit_code=exit_code,
        reasons=reasons,
        metadata={"pass_rate": pass_rate, "config": cfg.__dict__},
    )
