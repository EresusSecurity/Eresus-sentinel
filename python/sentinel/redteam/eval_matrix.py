"""Eval matrix runner — cross-product of prompts × providers × tests."""
from __future__ import annotations

import logging
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from sentinel.redteam.assertion_registry import AssertionRegistry, AssertionResult, AssertionSpec

logger = logging.getLogger(__name__)


@dataclass
class MatrixCell:
    prompt: str
    provider: str
    strategy: str
    output: str = ""
    assertions: list[AssertionResult] = field(default_factory=list)
    error: str = ""
    latency_ms: float = 0.0


@dataclass
class MatrixResult:
    cells: list[MatrixCell] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def total(self) -> int:
        return len(self.cells)

    @property
    def passed(self) -> int:
        return sum(1 for c in self.cells if all(
            a.status.value == "pass" for a in c.assertions
        ))

    @property
    def failed(self) -> int:
        return self.total - self.passed - self.errored

    @property
    def errored(self) -> int:
        return sum(1 for c in self.cells if c.error)

    def summary(self) -> dict[str, Any]:
        return {
            "total": self.total,
            "passed": self.passed,
            "failed": self.failed,
            "errored": self.errored,
            "pass_rate": self.passed / max(self.total, 1),
        }


class EvalMatrix:
    """Run assertion-based evaluation across a matrix of prompts × providers."""

    def __init__(self, registry: AssertionRegistry | None = None) -> None:
        self._registry = registry or AssertionRegistry()

    def run(
        self,
        prompts: list[str],
        providers: list[str],
        strategies: list[str],
        assertions: list[AssertionSpec],
        invoke_fn: Callable[[str, str, str], str] | None = None,
    ) -> MatrixResult:
        result = MatrixResult()
        if not strategies:
            strategies = ["default"]

        for prompt in prompts:
            for provider in providers:
                for strategy in strategies:
                    cell = MatrixCell(prompt=prompt, provider=provider, strategy=strategy)
                    try:
                        if invoke_fn:
                            cell.output = invoke_fn(prompt, provider, strategy)
                        else:
                            cell.output = f"[stub] No invoke_fn provided for {provider}"
                        cell.assertions = self._registry.evaluate_all(assertions, cell.output)
                    except Exception as e:
                        cell.error = str(e)
                    result.cells.append(cell)

        return result

    def format_table(self, result: MatrixResult) -> str:
        header = "| Prompt | Provider | Strategy | Pass | Errors |"
        sep = "| --- | --- | --- | --- | --- |"
        lines = [header, sep]
        for cell in result.cells:
            passed = sum(1 for a in cell.assertions if a.status.value == "pass")
            total = len(cell.assertions)
            prompt_short = cell.prompt[:40].replace("|", "\\|")
            err = cell.error or "-"
            lines.append(
                f"| {prompt_short} | {cell.provider}"
                f" | {cell.strategy} | {passed}/{total} | {err} |"
            )
        return "\n".join(lines)
