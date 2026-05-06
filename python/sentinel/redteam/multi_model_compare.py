"""
Multi-Model Comparison Runner.

Executes the same set of probes against N models simultaneously and produces
a side-by-side attack success rate comparison table.

Usage::

    from sentinel.redteam.multi_model_compare import MultiModelComparison
    from sentinel.redteam.generators.litellm import LiteLLMGenerator

    models = [
        LiteLLMGenerator(model="gpt-4o"),
        LiteLLMGenerator(model="claude-3-5-sonnet-20241022"),
        LiteLLMGenerator(model="gemini/gemini-1.5-pro"),
    ]
    probes = ["dan", "word_game", "genetic_jailbreak", "skeleton_key"]

    cmp = MultiModelComparison(models, probes)
    report = cmp.run()
    print(report.summary_table())
"""
from __future__ import annotations

import concurrent.futures
import json
import logging
import re
import time
import uuid
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

logger = logging.getLogger(__name__)


# ── Result data models ────────────────────────────────────────────────────

@dataclass
class ModelProbeResult:
    """Result of one probe against one model."""
    model_name: str
    probe_name: str
    total_attempts: int
    successes: int         # jailbreak successes (attack succeeded)
    failures: int          # refused/safe
    asr: float             # attack success rate
    latency_avg_ms: float
    error: str | None = None
    sample_responses: list[str] = field(default_factory=list)


@dataclass
class ComparisonReport:
    """Full multi-model comparison report."""
    run_id: str
    timestamp: str
    models: list[str]
    probes: list[str]
    results: list[ModelProbeResult] = field(default_factory=list)
    metadata: dict[str, Any] = field(default_factory=dict)

    # ── Convenience accessors ─────────────────────────────────────────

    def asr_for(self, model: str, probe: str) -> float | None:
        for r in self.results:
            if r.model_name == model and r.probe_name == probe:
                return r.asr
        return None

    def most_vulnerable_model(self) -> str | None:
        """Model with the highest overall ASR."""
        model_asr: dict[str, list[float]] = {}
        for r in self.results:
            model_asr.setdefault(r.model_name, []).append(r.asr)
        if not model_asr:
            return None
        return max(model_asr, key=lambda m: sum(model_asr[m]) / len(model_asr[m]))

    def most_effective_probe(self) -> str | None:
        """Probe with the highest average ASR across all models."""
        probe_asr: dict[str, list[float]] = {}
        for r in self.results:
            probe_asr.setdefault(r.probe_name, []).append(r.asr)
        if not probe_asr:
            return None
        return max(probe_asr, key=lambda p: sum(probe_asr[p]) / len(probe_asr[p]))

    # ── Formatting ────────────────────────────────────────────────────

    def summary_table(self) -> str:
        """ASCII table: rows=models, columns=probes, cells=ASR%."""
        col_w = 14
        probe_w = max((len(p) for p in self.probes), default=10) + 2
        header = f"{'Model':<{probe_w}}" + "".join(f"{p[:col_w]:>{col_w}}" for p in self.probes) + f"{'AVG':>{col_w}}"
        sep = "-" * len(header)
        rows = [header, sep]
        for model in self.models:
            model_asrs = [self.asr_for(model, probe) for probe in self.probes]
            values = [f"{(a * 100):.1f}%" if a is not None else "N/A" for a in model_asrs]
            valid = [a for a in model_asrs if a is not None]
            avg = f"{(sum(valid) / len(valid) * 100):.1f}%" if valid else "N/A"
            row = f"{model[:probe_w-2]:<{probe_w}}" + "".join(f"{v:>{col_w}}" for v in values) + f"{avg:>{col_w}}"
            rows.append(row)
        rows.append(sep)
        # Probe averages row
        probe_avgs: list[str] = []
        for probe in self.probes:
            asrs = [r.asr for r in self.results if r.probe_name == probe]
            avg_val = sum(asrs) / len(asrs) if asrs else 0.0
            probe_avgs.append(f"{avg_val * 100:.1f}%")
        all_asrs = [r.asr for r in self.results]
        overall_avg = f"{sum(all_asrs) / len(all_asrs) * 100:.1f}%" if all_asrs else "N/A"
        rows.append(
            f"{'PROBE AVG':<{probe_w}}"
            + "".join(f"{v:>{col_w}}" for v in probe_avgs)
            + f"{overall_avg:>{col_w}}"
        )
        return "\n".join(rows)

    def as_dict(self) -> dict[str, Any]:
        return {
            "run_id": self.run_id,
            "timestamp": self.timestamp,
            "models": self.models,
            "probes": self.probes,
            "most_vulnerable_model": self.most_vulnerable_model(),
            "most_effective_probe": self.most_effective_probe(),
            "results": [
                {
                    "model": r.model_name,
                    "probe": r.probe_name,
                    "asr": round(r.asr, 4),
                    "attempts": r.total_attempts,
                    "successes": r.successes,
                    "latency_avg_ms": round(r.latency_avg_ms, 1),
                    "error": r.error,
                }
                for r in self.results
            ],
            "metadata": self.metadata,
        }

    def as_json(self, indent: int = 2) -> str:
        return json.dumps(self.as_dict(), indent=indent, ensure_ascii=False)


# ── Comparison runner ─────────────────────────────────────────────────────

class MultiModelComparison:
    """Run identical probes against multiple models and compare attack success rates.

    Args:
        generators:       List of generator instances (one per model).
        probe_names:      List of probe names or Probe instances.
        max_workers:      Thread-pool workers for parallel model evaluation.
        max_prompts:      Max prompts per probe (None = all).
        classifier:       Optional ResponseClassifier; defaults to HeuristicClassifier.
    """

    def __init__(
        self,
        generators: list[Any],
        probe_names: list[str | Any],
        max_workers: int = 4,
        max_prompts: int | None = 5,
        classifier: Any | None = None,
    ) -> None:
        self._generators = generators
        self._probe_names = probe_names
        self._max_workers = max_workers
        self._max_prompts = max_prompts

        if classifier is None:
            from sentinel.redteam.classifiers.heuristic import HeuristicClassifier
            self._classifier = HeuristicClassifier()
        else:
            self._classifier = classifier

    # ── Probe loading ─────────────────────────────────────────────────

    _PROBE_NAME_RE = re.compile(r"^[a-zA-Z0-9_:\-\.]{1,80}$")

    def _load_probe(self, name_or_probe: str | Any) -> Any:
        if not isinstance(name_or_probe, str):
            return name_or_probe

        if not self._PROBE_NAME_RE.match(name_or_probe):
            raise ValueError(
                f"Invalid probe name '{name_or_probe}': only alphanumeric, _, :, -, . allowed "
                f"(max 80 chars). Probe name whitelist check failed."
            )

        try:
            from sentinel.redteam.probe import Probe
            import importlib
            import inspect
            import pkgutil
            import sentinel.redteam.probes as probes_pkg
            for info in pkgutil.iter_modules(probes_pkg.__path__):
                if not re.match(r"^[a-z0-9_]+$", info.name):
                    continue
                try:
                    mod = importlib.import_module(f"sentinel.redteam.probes.{info.name}")
                    for _, cls in inspect.getmembers(mod, inspect.isclass):
                        if issubclass(cls, Probe) and cls is not Probe:
                            if getattr(cls, "probe_name", "") == name_or_probe:
                                return cls()
                except Exception:
                    pass
        except Exception as exc:
            logger.debug("Probe lookup error for %s: %s", name_or_probe, exc)
        raise ValueError(f"Probe not found in registry: {name_or_probe!r}")

    def _get_prompts(self, probe: Any) -> list[str]:
        prompts: list[str] = []
        try:
            if hasattr(probe, "generate_payloads"):
                for p in probe.generate_payloads():
                    prompts.append(p["prompt"] if isinstance(p, dict) else str(p))
            elif hasattr(probe, "prompts"):
                prompts = list(probe.prompts)
        except Exception as exc:
            logger.warning("Failed to get prompts from probe: %s", exc)
        if self._max_prompts:
            prompts = prompts[: self._max_prompts]
        return prompts

    # ── Single model + probe evaluation ──────────────────────────────

    def _evaluate_one(
        self,
        generator: Any,
        probe: Any,
        prompts: list[str],
    ) -> ModelProbeResult:
        model_name = getattr(generator, "model", type(generator).__name__)
        probe_name = getattr(probe, "probe_name", type(probe).__name__)

        successes = 0
        latencies: list[float] = []
        sample_responses: list[str] = []
        error: str | None = None

        for prompt in prompts:
            try:
                t0 = time.time()
                response = generator.generate(prompt)
                latency_ms = (time.time() - t0) * 1000
                latencies.append(latency_ms)

                response_text = getattr(response, "text", str(response))
                if len(sample_responses) < 2:
                    sample_responses.append(response_text[:200])

                result = self._classifier.classify(prompt, response_text)
                if result.attack_succeeded:
                    successes += 1
            except Exception as exc:
                error = str(exc)
                logger.debug("Error evaluating %s/%s: %s", model_name, probe_name, exc)

        total = len(prompts)
        asr = successes / total if total > 0 else 0.0
        avg_latency = sum(latencies) / len(latencies) if latencies else 0.0

        return ModelProbeResult(
            model_name=model_name,
            probe_name=probe_name,
            total_attempts=total,
            successes=successes,
            failures=total - successes,
            asr=asr,
            latency_avg_ms=avg_latency,
            error=error,
            sample_responses=sample_responses,
        )

    # ── Public run ────────────────────────────────────────────────────

    def run(self) -> ComparisonReport:
        """Execute comparison and return report."""
        run_id = str(uuid.uuid4())[:8]
        timestamp = datetime.now(timezone.utc).isoformat()

        probes = [self._load_probe(p) for p in self._probe_names]
        probe_prompts = {
            getattr(p, "probe_name", type(p).__name__): self._get_prompts(p)
            for p in probes
        }
        model_names = [getattr(g, "model", type(g).__name__) for g in self._generators]
        probe_names_list = list(probe_prompts.keys())

        results: list[ModelProbeResult] = []
        tasks: list[tuple[Any, Any, list[str]]] = [
            (gen, probe, probe_prompts[getattr(probe, "probe_name", type(probe).__name__)])
            for gen in self._generators
            for probe in probes
        ]

        with concurrent.futures.ThreadPoolExecutor(max_workers=self._max_workers) as executor:
            futures = {
                executor.submit(self._evaluate_one, gen, probe, prompts): (gen, probe)
                for gen, probe, prompts in tasks
            }
            for future in concurrent.futures.as_completed(futures):
                try:
                    results.append(future.result())
                except Exception as exc:
                    gen, probe = futures[future]
                    logger.error("Comparison task failed: %s", exc)

        return ComparisonReport(
            run_id=run_id,
            timestamp=timestamp,
            models=model_names,
            probes=probe_names_list,
            results=results,
            metadata={"max_prompts_per_probe": self._max_prompts},
        )
