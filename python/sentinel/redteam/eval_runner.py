"""Config-driven LLM evaluation runner.

This module provides the productized eval surface behind ``sentinel evaluate
<config>``. It intentionally reuses the existing generator and assertion
registries instead of adding reference-tool-specific concepts to the public CLI.
"""

from __future__ import annotations

import csv
import json
import time
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

import yaml

from sentinel.redteam.assertion_registry import (
    AssertionRegistry,
    AssertionResult,
    AssertionSpec,
    AssertionStatus,
)
from sentinel.redteam.generators import get_generator


@dataclass
class EvalProviderSpec:
    """Provider configuration for one eval target."""

    id: str
    name: str
    model: str = ""
    config: dict[str, Any] = field(default_factory=dict)


@dataclass
class EvalCase:
    """One rendered prompt plus assertions."""

    id: str
    prompt: str
    variables: dict[str, Any] = field(default_factory=dict)
    assertions: list[AssertionSpec] = field(default_factory=list)
    source: str = "inline"
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class EvalCell:
    """One provider/case execution result."""

    case_id: str
    provider_id: str
    prompt: str
    output: str = ""
    model: str = ""
    latency_ms: float = 0.0
    input_tokens: int = 0
    output_tokens: int = 0
    total_tokens: int = 0
    assertions: list[AssertionResult] = field(default_factory=list)
    error: str = ""
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        if self.error:
            return False
        return all(result.status == AssertionStatus.PASS for result in self.assertions)

    @property
    def failed_assertions(self) -> list[AssertionResult]:
        return [
            result
            for result in self.assertions
            if result.status in (AssertionStatus.FAIL, AssertionStatus.ERROR)
        ]

    def to_dict(self) -> dict[str, Any]:
        return {
            "case_id": self.case_id,
            "provider_id": self.provider_id,
            "prompt": self.prompt,
            "output": self.output,
            "model": self.model,
            "latency_ms": round(self.latency_ms, 2),
            "input_tokens": self.input_tokens,
            "output_tokens": self.output_tokens,
            "total_tokens": self.total_tokens,
            "passed": self.passed,
            "error": self.error,
            "assertions": [
                {
                    "id": result.assertion_id,
                    "status": result.status.value,
                    "message": result.message,
                    "actual": result.actual,
                    "expected": result.expected,
                    "metadata": result.metadata,
                }
                for result in self.assertions
            ],
            "metadata": self.metadata,
        }


# Severity weight map for weighted_score() and grade_matrix()
_SEVERITY_WEIGHTS: dict[str, float] = {
    "critical": 4.0,
    "high":     3.0,
    "medium":   2.0,
    "low":      1.0,
    "info":     0.5,
}


@dataclass
class EvalRunResult:
    """Complete eval run result."""

    id: str
    name: str
    providers: list[EvalProviderSpec]
    cases: list[EvalCase]
    cells: list[EvalCell]
    duration_ms: float
    metadata: dict[str, Any] = field(default_factory=dict)

    @property
    def passed(self) -> bool:
        return all(cell.passed for cell in self.cells)

    def summary(self) -> dict[str, Any]:
        total = len(self.cells)
        failed = sum(1 for cell in self.cells if not cell.passed)
        errors = sum(1 for cell in self.cells if cell.error)
        assertions = sum(len(cell.assertions) for cell in self.cells)
        assertion_failures = sum(len(cell.failed_assertions) for cell in self.cells)
        return {
            "id": self.id,
            "name": self.name,
            "providers": len(self.providers),
            "cases": len(self.cases),
            "cells": total,
            "passed": total - failed,
            "failed": failed,
            "errors": errors,
            "assertions": assertions,
            "assertion_failures": assertion_failures,
            "pass_rate": ((total - failed) / total) if total else 0.0,
            "weighted_score": self.weighted_score(),
            "duration_ms": round(self.duration_ms, 2),
        }

    # ── Severity-weighted score ───────────────────────────────

    def weighted_score(self) -> float:
        """Compute a severity-weighted pass score in [0.0, 1.0].

        Each cell contributes ``weight * pass_value`` to the numerator
        and ``weight`` to the denominator, where *weight* is derived
        from the cell's ``metadata["severity"]`` (default "medium").
        Cells with errors count as fails at their full weight.

        A score of 1.0 means all cells passed; 0.0 means all failed.
        """
        total_weight = 0.0
        weighted_pass = 0.0
        for cell in self.cells:
            severity = str(cell.metadata.get("severity", "medium")).lower()
            weight = _SEVERITY_WEIGHTS.get(severity, 2.0)
            total_weight += weight
            if cell.passed:
                weighted_pass += weight
        return (weighted_pass / total_weight) if total_weight else 0.0

    # ── Per-provider × per-category accuracy matrix ───────────

    def grade_matrix(self) -> dict[str, Any]:
        """Return a per-provider × per-category accuracy table.

        Returns a dict::

            {
                "providers": ["provider-a", "provider-b", ...],
                "categories": ["injection", "jailbreak", ...],
                "matrix": {
                    "provider-a": {
                        "injection": {"pass": 3, "fail": 1, "accuracy": 0.75},
                        ...
                        "_total": {"pass": N, "fail": M, "accuracy": X, "weighted_score": Y}
                    },
                    ...
                }
            }

        Categories are drawn from ``cell.metadata["category"]`` (falls
        back to ``case.metadata["category"]`` if not set on the cell).
        Cells without a category are bucketed as ``"_uncategorized"``.
        """
        # Build case_id → case metadata lookup for category fallback
        case_meta: dict[str, dict[str, Any]] = {c.id: c.metadata for c in self.cases}

        # Collect all unique categories and provider ids
        provider_ids: list[str] = [p.id for p in self.providers]
        categories: set[str] = set()
        for cell in self.cells:
            cat = (
                cell.metadata.get("category")
                or case_meta.get(cell.case_id, {}).get("category")
                or "_uncategorized"
            )
            categories.add(cat)

        sorted_cats = sorted(categories)

        # cell counts: provider → category → {pass, fail}
        counts: dict[str, dict[str, dict[str, int]]] = {
            pid: {cat: {"pass": 0, "fail": 0} for cat in sorted_cats + ["_total"]}
            for pid in provider_ids
        }

        for cell in self.cells:
            if cell.provider_id not in counts:
                continue
            cat = (
                cell.metadata.get("category")
                or case_meta.get(cell.case_id, {}).get("category")
                or "_uncategorized"
            )
            result_key = "pass" if cell.passed else "fail"
            counts[cell.provider_id][cat][result_key] += 1
            counts[cell.provider_id]["_total"][result_key] += 1

        # Build output matrix with accuracy + weighted_score per provider
        matrix: dict[str, dict[str, Any]] = {}
        for pid in provider_ids:
            row: dict[str, Any] = {}
            # Per-category rows
            for cat in sorted_cats:
                p = counts[pid][cat]["pass"]
                f = counts[pid][cat]["fail"]
                total = p + f
                row[cat] = {
                    "pass": p,
                    "fail": f,
                    "accuracy": (p / total) if total else None,
                }
            # Total row with weighted_score (subset of self.cells for this provider)
            provider_cells = [c for c in self.cells if c.provider_id == pid]
            total_p = counts[pid]["_total"]["pass"]
            total_f = counts[pid]["_total"]["fail"]
            total_n = total_p + total_f
            # Weighted score for this provider
            tw, wp = 0.0, 0.0
            for cell in provider_cells:
                severity = str(cell.metadata.get("severity", "medium")).lower()
                w = _SEVERITY_WEIGHTS.get(severity, 2.0)
                tw += w
                if cell.passed:
                    wp += w
            row["_total"] = {
                "pass": total_p,
                "fail": total_f,
                "accuracy": (total_p / total_n) if total_n else None,
                "weighted_score": (wp / tw) if tw else None,
            }
            matrix[pid] = row

        return {
            "providers": provider_ids,
            "categories": sorted_cats,
            "matrix": matrix,
        }

    # ── Precision / recall per provider+category ─────────────

    def precision_recall(self) -> dict[str, Any]:
        """Per-provider × per-category precision and recall.

        Requires cells to have ``metadata["expected"]`` set to
        ``"pass"`` or ``"fail"`` (ground-truth label). Cells without
        the key are excluded from the calculation.

        Returns::

            {
                "provider-a": {
                    "injection": {
                        "TP": 3, "FP": 1, "FN": 0, "TN": 2,
                        "precision": 0.75, "recall": 1.0, "f1": 0.857
                    },
                    ...
                },
                ...
            }
        """
        case_meta: dict[str, dict[str, Any]] = {c.id: c.metadata for c in self.cases}
        result: dict[str, dict[str, Any]] = {}

        for provider in self.providers:
            pid = provider.id
            category_stats: dict[str, dict[str, int]] = {}

            for cell in self.cells:
                if cell.provider_id != pid:
                    continue
                expected_raw = (
                    cell.metadata.get("expected")
                    or case_meta.get(cell.case_id, {}).get("expected")
                )
                if expected_raw is None:
                    continue

                expected_pass = str(expected_raw).lower() in ("pass", "true", "1")
                actual_pass = cell.passed

                cat = (
                    cell.metadata.get("category")
                    or case_meta.get(cell.case_id, {}).get("category")
                    or "_uncategorized"
                )
                if cat not in category_stats:
                    category_stats[cat] = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}

                if expected_pass and actual_pass:
                    category_stats[cat]["TP"] += 1
                elif not expected_pass and actual_pass:
                    category_stats[cat]["FP"] += 1
                elif expected_pass and not actual_pass:
                    category_stats[cat]["FN"] += 1
                else:
                    category_stats[cat]["TN"] += 1

            cat_metrics: dict[str, Any] = {}
            for cat, s in category_stats.items():
                tp, fp, fn = s["TP"], s["FP"], s["FN"]
                precision = tp / (tp + fp) if (tp + fp) else None
                recall = tp / (tp + fn) if (tp + fn) else None
                if precision is not None and recall is not None:
                    denom = precision + recall
                    f1: float | None = (2 * precision * recall / denom) if denom else 0.0
                else:
                    f1 = None
                cat_metrics[cat] = {**s, "precision": precision, "recall": recall, "f1": f1}

            result[pid] = cat_metrics

        return result
        """Compute a severity-weighted pass score in [0.0, 1.0].

        Each cell contributes ``weight * pass_value`` to the numerator
        and ``weight`` to the denominator, where *weight* is derived
        from the cell's ``metadata["severity"]`` (default "medium").
        Cells with errors count as fails at their full weight.

        A score of 1.0 means all cells passed; 0.0 means all failed.
        """
        total_weight = 0.0
        weighted_pass = 0.0
        for cell in self.cells:
            severity = str(cell.metadata.get("severity", "medium")).lower()
            weight = _SEVERITY_WEIGHTS.get(severity, 2.0)
            total_weight += weight
            if cell.passed:
                weighted_pass += weight
        return (weighted_pass / total_weight) if total_weight else 0.0

    # ── Per-provider × per-category accuracy matrix ───────────

    def grade_matrix(self) -> dict[str, Any]:
        """Return a per-provider × per-category accuracy table.

        Returns a dict::

            {
                "providers": ["provider-a", "provider-b", ...],
                "categories": ["injection", "jailbreak", ...],
                "matrix": {
                    "provider-a": {
                        "injection": {"pass": 3, "fail": 1, "accuracy": 0.75},
                        ...
                        "_total": {"pass": N, "fail": M, "accuracy": X, "weighted_score": Y}
                    },
                    ...
                }
            }

        Categories are drawn from ``cell.metadata["category"]`` (falls
        back to ``case.metadata["category"]`` if not set on the cell).
        Cells without a category are bucketed as ``"_uncategorized"``.
        """
        # Build case_id → case metadata lookup for category fallback
        case_meta: dict[str, dict[str, Any]] = {c.id: c.metadata for c in self.cases}

        # Collect all unique categories and provider ids
        provider_ids: list[str] = [p.id for p in self.providers]
        categories: set[str] = set()
        for cell in self.cells:
            cat = (
                cell.metadata.get("category")
                or case_meta.get(cell.case_id, {}).get("category")
                or "_uncategorized"
            )
            categories.add(cat)

        sorted_cats = sorted(categories)

        # cell counts: provider → category → {pass, fail}
        counts: dict[str, dict[str, dict[str, int]]] = {
            pid: {cat: {"pass": 0, "fail": 0} for cat in sorted_cats + ["_total"]}
            for pid in provider_ids
        }

        for cell in self.cells:
            if cell.provider_id not in counts:
                continue
            cat = (
                cell.metadata.get("category")
                or case_meta.get(cell.case_id, {}).get("category")
                or "_uncategorized"
            )
            result_key = "pass" if cell.passed else "fail"
            counts[cell.provider_id][cat][result_key] += 1
            counts[cell.provider_id]["_total"][result_key] += 1

        # Build output matrix with accuracy + weighted_score per provider
        matrix: dict[str, dict[str, Any]] = {}
        for pid in provider_ids:
            row: dict[str, Any] = {}
            # Per-category rows
            for cat in sorted_cats:
                p = counts[pid][cat]["pass"]
                f = counts[pid][cat]["fail"]
                total = p + f
                row[cat] = {
                    "pass": p,
                    "fail": f,
                    "accuracy": (p / total) if total else None,
                }
            # Total row with weighted_score (subset of self.cells for this provider)
            provider_cells = [c for c in self.cells if c.provider_id == pid]
            total_p = counts[pid]["_total"]["pass"]
            total_f = counts[pid]["_total"]["fail"]
            total_n = total_p + total_f
            # Weighted score for this provider
            tw, wp = 0.0, 0.0
            for cell in provider_cells:
                severity = str(cell.metadata.get("severity", "medium")).lower()
                w = _SEVERITY_WEIGHTS.get(severity, 2.0)
                tw += w
                if cell.passed:
                    wp += w
            row["_total"] = {
                "pass": total_p,
                "fail": total_f,
                "accuracy": (total_p / total_n) if total_n else None,
                "weighted_score": (wp / tw) if tw else None,
            }
            matrix[pid] = row

        return {
            "providers": provider_ids,
            "categories": sorted_cats,
            "matrix": matrix,
        }

    # ── Precision / recall per provider+category ─────────────

    def precision_recall(self) -> dict[str, Any]:
        """Per-provider × per-category precision and recall.

        Requires cells to have ``metadata["expected"]`` set to
        ``"pass"`` or ``"fail"`` (ground-truth label). Cells without
        the key are excluded from the calculation.

        Returns::

            {
                "provider-a": {
                    "injection": {
                        "TP": 3, "FP": 1, "FN": 0, "TN": 2,
                        "precision": 0.75, "recall": 1.0, "f1": 0.857
                    },
                    ...
                },
                ...
            }
        """
        case_meta: dict[str, dict[str, Any]] = {c.id: c.metadata for c in self.cases}
        result: dict[str, dict[str, Any]] = {}

        for provider in self.providers:
            pid = provider.id
            category_stats: dict[str, dict[str, int]] = {}

            for cell in self.cells:
                if cell.provider_id != pid:
                    continue
                expected_raw = (
                    cell.metadata.get("expected")
                    or case_meta.get(cell.case_id, {}).get("expected")
                )
                if expected_raw is None:
                    continue

                expected_pass = str(expected_raw).lower() in ("pass", "true", "1")
                actual_pass = cell.passed

                cat = (
                    cell.metadata.get("category")
                    or case_meta.get(cell.case_id, {}).get("category")
                    or "_uncategorized"
                )
                if cat not in category_stats:
                    category_stats[cat] = {"TP": 0, "FP": 0, "FN": 0, "TN": 0}

                if expected_pass and actual_pass:
                    category_stats[cat]["TP"] += 1
                elif not expected_pass and actual_pass:
                    category_stats[cat]["FP"] += 1
                elif expected_pass and not actual_pass:
                    category_stats[cat]["FN"] += 1
                else:
                    category_stats[cat]["TN"] += 1

            cat_metrics: dict[str, Any] = {}
            for cat, s in category_stats.items():
                tp, fp, fn = s["TP"], s["FP"], s["FN"]
                precision = tp / (tp + fp) if (tp + fp) else None
                recall = tp / (tp + fn) if (tp + fn) else None
                if precision is not None and recall is not None:
                    denom = precision + recall
                    f1: float | None = (2 * precision * recall / denom) if denom else 0.0
                else:
                    f1 = None
                cat_metrics[cat] = {**s, "precision": precision, "recall": recall, "f1": f1}

            result[pid] = cat_metrics

        return result

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.id,
            "name": self.name,
            "summary": self.summary(),
            "providers": [
                {
                    "id": provider.id,
                    "name": provider.name,
                    "model": provider.model,
                    "config": provider.config,
                }
                for provider in self.providers
            ],
            "cases": [
                {
                    "id": case.id,
                    "prompt": case.prompt,
                    "variables": case.variables,
                    "source": case.source,
                    "metadata": case.metadata,
                    "assertions": [assertion.id for assertion in case.assertions],
                }
                for case in self.cases
            ],
            "cells": [cell.to_dict() for cell in self.cells],
            "metadata": self.metadata,
        }


@dataclass
class EvalConfig:
    """Parsed eval config."""

    id: str
    name: str
    providers: list[EvalProviderSpec]
    cases: list[EvalCase]
    metadata: dict[str, Any] = field(default_factory=dict)


class EvalRunner:
    """Run deterministic eval configs against registered generators."""

    def __init__(self, assertion_registry: AssertionRegistry | None = None) -> None:
        self._assertions = assertion_registry or AssertionRegistry()

    def run_file(self, path: str | Path) -> EvalRunResult:
        return self.run(load_eval_config(path))

    def run(self, config: EvalConfig) -> EvalRunResult:
        start = time.perf_counter()
        provider_instances = {
            provider.id: self._build_generator(provider)
            for provider in config.providers
        }
        cells: list[EvalCell] = []

        for provider in config.providers:
            generator = provider_instances[provider.id]
            for case in config.cases:
                cell_start = time.perf_counter()
                cell = EvalCell(
                    case_id=case.id,
                    provider_id=provider.id,
                    prompt=case.prompt,
                    metadata={"source": case.source, **case.metadata},
                )
                try:
                    response = generator.generate(case.prompt)
                    cell.latency_ms = (time.perf_counter() - cell_start) * 1000
                    cell.output = response.text
                    cell.model = response.model or provider.model
                    cell.input_tokens = response.input_tokens
                    cell.output_tokens = response.output_tokens
                    cell.total_tokens = response.total_tokens
                    cell.assertions = self._assertions.evaluate_all(
                        case.assertions,
                        response.text,
                    )
                except Exception as exc:
                    cell.latency_ms = (time.perf_counter() - cell_start) * 1000
                    cell.error = str(exc)
                cells.append(cell)

        duration_ms = (time.perf_counter() - start) * 1000
        return EvalRunResult(
            id=config.id,
            name=config.name,
            providers=config.providers,
            cases=config.cases,
            cells=cells,
            duration_ms=duration_ms,
            metadata=config.metadata,
        )

    @staticmethod
    def _build_generator(provider: EvalProviderSpec):
        kwargs = dict(provider.config)
        if provider.model:
            kwargs.setdefault("model", provider.model)
        return get_generator(provider.name, **kwargs)


def run_eval_file(path: str | Path) -> EvalRunResult:
    """Convenience wrapper for CLI/API callers."""

    return EvalRunner().run_file(path)


def load_eval_config(path: str | Path) -> EvalConfig:
    """Load a YAML/JSON eval config."""

    config_path = Path(path)
    raw = _load_structured_file(config_path)
    if not isinstance(raw, dict):
        raise ValueError("Eval config must be a mapping")

    global_vars = _as_dict(raw.get("vars") or raw.get("variables") or {})
    global_assertions = _parse_assertions(raw.get("assertions", []), prefix="global")
    providers = _parse_providers(raw.get("providers") or [{"name": "echo"}])
    cases = _parse_cases(raw, global_vars, global_assertions, config_path)
    if not cases:
        raise ValueError("Eval config must define at least one prompt, test, or dataset row")

    return EvalConfig(
        id=str(raw.get("id") or config_path.stem),
        name=str(raw.get("name") or raw.get("description") or config_path.stem),
        providers=providers,
        cases=cases,
        metadata=_as_dict(raw.get("metadata") or {}),
    )


def format_eval_markdown(result: EvalRunResult) -> str:
    """Render a compact Markdown report."""

    summary = result.summary()
    lines = [
        f"# Eval Report: {result.name}",
        "",
        "| Metric | Value |",
        "| --- | ---: |",
    ]
    for key in (
        "providers",
        "cases",
        "cells",
        "passed",
        "failed",
        "errors",
        "assertions",
        "assertion_failures",
        "pass_rate",
        "duration_ms",
    ):
        value = summary[key]
        if key == "pass_rate":
            value = f"{value:.1%}"
        lines.append(f"| {key} | {value} |")

    lines.extend(
        [
            "",
            "| Case | Provider | Status | Latency ms | Error |",
            "| --- | --- | --- | ---: | --- |",
        ]
    )
    for cell in result.cells:
        status = "PASS" if cell.passed else "FAIL"
        error = cell.error or "; ".join(f.message for f in cell.failed_assertions)
        lines.append(
            f"| {cell.case_id} | {cell.provider_id} | {status} | "
            f"{cell.latency_ms:.1f} | {error} |"
        )
    return "\n".join(lines) + "\n"


def _load_structured_file(path: Path) -> Any:
    if not path.exists():
        raise FileNotFoundError(f"Eval config not found: {path}")
    text = path.read_text(encoding="utf-8")
    if path.suffix.lower() in {".yaml", ".yml"}:
        return yaml.safe_load(text) or {}
    return json.loads(text)


def _parse_providers(raw_providers: Any) -> list[EvalProviderSpec]:
    providers: list[EvalProviderSpec] = []
    for idx, item in enumerate(_ensure_list(raw_providers)):
        if isinstance(item, str):
            providers.append(EvalProviderSpec(id=item, name=item))
            continue
        if not isinstance(item, dict):
            raise ValueError(f"Provider #{idx + 1} must be a string or mapping")
        name = str(item.get("name") or item.get("provider") or item.get("type") or "echo")
        provider_id = str(item.get("id") or item.get("label") or name)
        config = _as_dict(item.get("config") or item.get("options") or {})
        for key, value in item.items():
            if key not in {"id", "label", "name", "provider", "type", "model", "config", "options"}:
                config.setdefault(key, value)
        providers.append(
            EvalProviderSpec(
                id=provider_id,
                name=name,
                model=str(item.get("model") or ""),
                config=config,
            )
        )
    return providers


def _expand_matrix(matrix: dict[str, Any]) -> list[dict[str, Any]]:
    """Cartesian-expand a matrix mapping of {key: [v1, v2, ...]} into variable dicts."""
    import itertools

    if not matrix:
        return [{}]
    keys = list(matrix.keys())
    value_lists = [_ensure_list(matrix[k]) for k in keys]
    return [dict(zip(keys, combo)) for combo in itertools.product(*value_lists)]


def _parse_cases(
    raw: dict[str, Any],
    global_vars: dict[str, Any],
    global_assertions: list[AssertionSpec],
    config_path: Path,
) -> list[EvalCase]:
    prompts = _parse_prompt_entries(raw.get("prompts") or raw.get("prompt") or [])
    tests = _ensure_list(raw.get("tests") or raw.get("cases") or [])
    cases: list[EvalCase] = []

    # Matrix expansion: cartesian product of variable axes
    matrix_raw = raw.get("matrix") or {}
    matrix_combos = _expand_matrix(matrix_raw) if matrix_raw else [{}]

    for matrix_vars in matrix_combos:
        combo_global = {**global_vars, **matrix_vars}
        combo_suffix = (
            "::" + ":".join(f"{k}={v}" for k, v in matrix_vars.items())
            if matrix_vars else ""
        )

        if tests:
            combo_cases = _cases_from_tests(prompts, tests, combo_global, global_assertions)
            for case in combo_cases:
                if combo_suffix:
                    case = EvalCase(
                        id=case.id + combo_suffix,
                        prompt=case.prompt,
                        variables={**case.variables, **matrix_vars},
                        assertions=case.assertions,
                        source=case.source,
                        metadata=case.metadata,
                    )
                cases.append(case)
        elif prompts:
            for prompt in prompts:
                variables = {**combo_global, **prompt["vars"]}
                cases.append(
                    EvalCase(
                        id=prompt["id"] + combo_suffix,
                        prompt=_render_template(prompt["prompt"], variables),
                        variables=variables,
                        assertions=[*global_assertions, *prompt["assertions"]],
                        source=prompt["source"],
                        metadata=prompt["metadata"],
                    )
                )

    for dataset in _ensure_list(raw.get("datasets") or []):
        cases.extend(_cases_from_dataset(dataset, global_vars, global_assertions, config_path))

    return cases


def _cases_from_tests(
    prompts: list[dict[str, Any]],
    tests: list[Any],
    global_vars: dict[str, Any],
    global_assertions: list[AssertionSpec],
) -> list[EvalCase]:
    cases: list[EvalCase] = []
    for test_idx, test in enumerate(tests, start=1):
        if not isinstance(test, dict):
            test = {"prompt": str(test)}
        test_id = str(test.get("id") or test.get("name") or f"test-{test_idx}")
        test_vars = _as_dict(test.get("vars") or test.get("variables") or {})
        test_assertions = _parse_assertions(
            test.get("assertions") or _assertions_from_expected(test),
            prefix=test_id,
        )

        if _entry_prompt(test):
            variables = {**global_vars, **test_vars}
            cases.append(
                EvalCase(
                    id=test_id,
                    prompt=_render_template(_entry_prompt(test), variables),
                    variables=variables,
                    assertions=[*global_assertions, *test_assertions],
                    source="test",
                    metadata=_as_dict(test.get("metadata") or {}),
                )
            )
            continue

        for prompt in prompts:
            variables = {**global_vars, **prompt["vars"], **test_vars}
            cases.append(
                EvalCase(
                    id=f"{prompt['id']}::{test_id}",
                    prompt=_render_template(prompt["prompt"], variables),
                    variables=variables,
                    assertions=[*global_assertions, *prompt["assertions"], *test_assertions],
                    source=prompt["source"],
                    metadata={**prompt["metadata"], **_as_dict(test.get("metadata") or {})},
                )
            )
    return cases


def _parse_prompt_entries(raw_prompts: Any) -> list[dict[str, Any]]:
    entries: list[dict[str, Any]] = []
    for idx, item in enumerate(_ensure_list(raw_prompts), start=1):
        if isinstance(item, str):
            entries.append(
                {
                    "id": f"prompt-{idx}",
                    "prompt": item,
                    "vars": {},
                    "assertions": [],
                    "source": "prompt",
                    "metadata": {},
                }
            )
            continue
        if not isinstance(item, dict):
            raise ValueError(f"Prompt #{idx} must be a string or mapping")
        text = _entry_prompt(item)
        if not text:
            raise ValueError(f"Prompt #{idx} is missing prompt/input/text")
        prompt_id = str(item.get("id") or item.get("name") or f"prompt-{idx}")
        entries.append(
            {
                "id": prompt_id,
                "prompt": text,
                "vars": _as_dict(item.get("vars") or item.get("variables") or {}),
                "assertions": _parse_assertions(item.get("assertions", []), prefix=prompt_id),
                "source": str(item.get("source") or "prompt"),
                "metadata": _as_dict(item.get("metadata") or {}),
            }
        )
    return entries


def _cases_from_dataset(
    dataset: Any,
    global_vars: dict[str, Any],
    global_assertions: list[AssertionSpec],
    config_path: Path,
) -> list[EvalCase]:
    if isinstance(dataset, str):
        dataset = {"path": dataset}
    if not isinstance(dataset, dict):
        raise ValueError("Dataset entries must be strings or mappings")
    dataset_path = Path(str(dataset.get("path") or ""))
    if not dataset_path.is_absolute():
        dataset_path = config_path.parent / dataset_path
    rows = _load_dataset_rows(dataset_path)
    dataset_id = str(dataset.get("id") or dataset_path.stem)
    dataset_assertions = _parse_assertions(dataset.get("assertions", []), prefix=dataset_id)
    prompt_template = dataset.get("prompt") or dataset.get("template")

    cases: list[EvalCase] = []
    for idx, row in enumerate(rows, start=1):
        variables = {**global_vars, **_as_dict(dataset.get("vars") or {}), **row}
        prompt = str(
            prompt_template
            or row.get("prompt")
            or row.get("input")
            or row.get("text")
            or ""
        )
        if not prompt:
            continue
        row_assertions = _parse_assertions(
            row.get("assertions") or _assertions_from_expected(row),
            prefix=f"{dataset_id}-{idx}",
        )
        cases.append(
            EvalCase(
                id=str(row.get("id") or f"{dataset_id}-{idx}"),
                prompt=_render_template(prompt, variables),
                variables=variables,
                assertions=[*global_assertions, *dataset_assertions, *row_assertions],
                source=str(dataset_path),
                metadata={"dataset": dataset_id},
            )
        )
    return cases


def _load_dataset_rows(path: Path) -> list[dict[str, Any]]:
    if not path.exists():
        raise FileNotFoundError(f"Eval dataset not found: {path}")
    suffix = path.suffix.lower()
    if suffix == ".jsonl":
        rows = []
        for line in path.read_text(encoding="utf-8").splitlines():
            if line.strip():
                item = json.loads(line)
                if isinstance(item, dict):
                    rows.append(item)
        return rows
    if suffix == ".csv":
        with open(path, newline="", encoding="utf-8") as handle:
            return [dict(row) for row in csv.DictReader(handle)]
    data = _load_structured_file(path)
    if isinstance(data, list):
        return [row for row in data if isinstance(row, dict)]
    if isinstance(data, dict) and isinstance(data.get("rows"), list):
        return [row for row in data["rows"] if isinstance(row, dict)]
    raise ValueError(f"Unsupported dataset shape: {path}")


def _parse_assertions(raw_assertions: Any, prefix: str) -> list[AssertionSpec]:
    assertions: list[AssertionSpec] = []
    for idx, item in enumerate(_ensure_list(raw_assertions), start=1):
        if isinstance(item, str):
            assertions.append(
                AssertionSpec(
                    id=f"{prefix}-contains-{idx}",
                    type="contains",
                    expected=item,
                )
            )
            continue
        if not isinstance(item, dict):
            raise ValueError(f"Assertion #{idx} must be a string or mapping")
        assertion_type = str(item.get("type") or item.get("assert") or "contains")
        metadata = _as_dict(item.get("metadata") or {})
        if "path" in item:
            metadata.setdefault("path", item["path"])
        expected = item.get("expected", item.get("value", item.get("contains")))
        assertions.append(
            AssertionSpec(
                id=str(item.get("id") or f"{prefix}-{assertion_type}-{idx}"),
                type=assertion_type,
                description=str(item.get("description") or ""),
                expected=expected,
                negate=bool(item.get("negate", False)),
                metadata=metadata,
            )
        )
    return assertions


def _assertions_from_expected(item: dict[str, Any]) -> list[dict[str, Any]]:
    if "expected" not in item:
        return []
    assertion_type = str(item.get("assertion") or item.get("assert") or "contains")
    return [{"type": assertion_type, "expected": item["expected"]}]


def _render_template(template: str, variables: dict[str, Any]) -> str:
    rendered = str(template)
    for key, value in variables.items():
        rendered = rendered.replace("{{" + str(key) + "}}", str(value))
        rendered = rendered.replace("{{ " + str(key) + " }}", str(value))
    return rendered


def _entry_prompt(item: dict[str, Any]) -> str:
    return str(
        item.get("prompt")
        or item.get("input")
        or item.get("text")
        or item.get("content")
        or ""
    )


def _ensure_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]


def _as_dict(value: Any) -> dict[str, Any]:
    return value if isinstance(value, dict) else {}
