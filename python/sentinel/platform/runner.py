from __future__ import annotations

import time
from pathlib import Path
from typing import Any

from sentinel.platform.assertions import AssertionRegistry
from sentinel.platform.config import ResolvedConfig, lint_config, resolve_config
from sentinel.platform.dataset import Dataset, inline_dataset, load_dataset
from sentinel.platform.formats import as_list, stable_sha256
from sentinel.platform.providers import ProviderRegistry, ProviderRequest
from sentinel.platform.store import RunStore, stable_id


def _render_template(template: str, variables: dict[str, Any]) -> str:
    rendered = template
    for key in sorted(variables):
        rendered = rendered.replace("{{" + str(key) + "}}", str(variables[key]))
        rendered = rendered.replace("${" + str(key) + "}", str(variables[key]))
    return rendered


class EvalRunner:
    def __init__(
        self,
        store: RunStore | None = None,
        providers: ProviderRegistry | None = None,
        assertions: AssertionRegistry | None = None,
    ) -> None:
        self.store = store or RunStore()
        self.providers = providers or ProviderRegistry()
        self.assertions = assertions or AssertionRegistry()

    def load(self, paths: list[str | Path], profile: str | None = None, environment: str | None = None, overrides: dict[str, Any] | None = None) -> ResolvedConfig:
        resolved = resolve_config(paths, profile=profile, environment=environment, overrides=overrides)
        issues = lint_config(resolved.data)
        errors = [issue for issue in issues if issue["severity"] == "error"]
        if errors:
            raise ValueError("; ".join(issue["message"] for issue in errors))
        return resolved

    def plan(self, config: dict[str, Any], base_dir: str | Path = ".") -> dict[str, Any]:
        prompts = self._prompts(config)
        providers = self._providers(config)
        datasets = self._datasets(config, base_dir)
        assertions = as_list(config.get("assertions"))
        cells = []
        for prompt in prompts:
            for provider in providers:
                for dataset in datasets:
                    for record in dataset.records:
                        variables = {**dict(config.get("defaults", {})), **record.variables}
                        cell_material = {
                            "prompt": prompt,
                            "provider": provider,
                            "dataset": dataset.fingerprint,
                            "record": record.id,
                            "assertions": assertions,
                        }
                        cells.append(
                            {
                                "id": stable_id("cell", cell_material),
                                "prompt_id": prompt["id"],
                                "provider": provider["id"],
                                "model": provider.get("model", "default"),
                                "dataset_id": dataset.id,
                                "record_id": record.id,
                                "variables": variables,
                            }
                        )
        return {
            "schema_version": "sentinel.eval.plan.v1",
            "cell_count": len(cells),
            "assertion_count": len(assertions),
            "cells": cells,
        }

    def run(
        self,
        paths: list[str | Path],
        profile: str | None = None,
        environment: str | None = None,
        overrides: dict[str, Any] | None = None,
        base_dir: str | Path | None = None,
    ) -> dict[str, Any]:
        resolved = self.load(paths, profile=profile, environment=environment, overrides=overrides)
        root = Path(base_dir) if base_dir else Path(paths[0]).parent if paths else Path(".")
        config = resolved.data
        plan = self.plan(config, root)
        run_id = stable_id("run", {"config": resolved.fingerprint, "plan": plan["cell_count"]})
        started = time.time()
        run = {
            "id": run_id,
            "schema_version": "sentinel.run.v1",
            "name": str(config.get("name") or "sentinel-eval"),
            "status": "running",
            "fingerprint": resolved.fingerprint,
            "started_at": started,
            "config": config,
            "summary": {"cells": 0, "passed": 0, "failed": 0},
        }
        self.store.put_run(run)
        self.store.put_trace(run_id, "run.started", {"plan": {"cell_count": plan["cell_count"]}})
        prompts = {prompt["id"]: prompt for prompt in self._prompts(config)}
        providers = {provider["id"]: provider for provider in self._providers(config)}
        assertion_specs = as_list(config.get("assertions"))
        totals = {"cells": 0, "passed": 0, "failed": 0, "assertions": 0}
        cell_results = []
        for cell in plan["cells"]:
            prompt = prompts[cell["prompt_id"]]
            provider_config = providers[cell["provider"]]
            provider = self.providers.get(provider_config["type"])
            rendered = _render_template(prompt["template"], cell["variables"])
            response = provider.generate(
                ProviderRequest(rendered, cell["variables"], model=provider_config.get("model"), timeout_s=float(provider_config.get("timeout_s", 30))),
                provider_config,
            )
            context = {
                "latency_ms": response.latency_ms,
                "input_tokens": response.input_tokens,
                "output_tokens": response.output_tokens,
                "cost_usd": response.cost_usd,
                "trace": [{"name": "provider.generate", "provider": response.provider}],
                **response.metadata,
            }
            outcomes = [self.assertions.evaluate(spec, response.output, context) for spec in assertion_specs]
            passed = all(outcome.passed for outcome in outcomes)
            totals["cells"] += 1
            totals["assertions"] += len(outcomes)
            totals["passed" if passed else "failed"] += 1
            stored_cell = {
                **cell,
                "run_id": run_id,
                "status": "passed" if passed else "failed",
                "output": response.output,
                "metadata": {"prompt": rendered, "provider_metadata": response.metadata},
            }
            self.store.put_cell(stored_cell)
            call = {
                "id": stable_id("call", {"cell": cell["id"], "response": response.__dict__}),
                "run_id": run_id,
                "cell_id": cell["id"],
                "provider": response.provider,
                "model": response.model,
                "latency_ms": response.latency_ms,
                "input_tokens": response.input_tokens,
                "output_tokens": response.output_tokens,
                "cost_usd": response.cost_usd,
                "metadata": response.metadata,
            }
            self.store.put_provider_call(call)
            for outcome in outcomes:
                outcome_data = outcome.__dict__
                self.store.put_assertion(
                    {
                        "id": stable_id("assertion", {"cell": cell["id"], "outcome": outcome.__dict__}),
                        "run_id": run_id,
                        "cell_id": cell["id"],
                        "type": outcome_data["type"],
                        "passed": outcome_data["passed"],
                        "score": outcome_data["score"],
                        "message": outcome_data["message"],
                        "evidence": {"assertion_id": outcome_data["id"], **outcome_data["evidence"]},
                    }
                )
            self.store.put_trace(run_id, "cell.finished", {"cell_id": cell["id"], "status": stored_cell["status"]}, cell["id"])
            cell_results.append({**stored_cell, "assertions": [outcome.__dict__ for outcome in outcomes], "provider_call": call})
        summary = {
            **totals,
            "pass_rate": totals["passed"] / totals["cells"] if totals["cells"] else 1.0,
            "exit_code": 0 if totals["failed"] == 0 else 1,
        }
        run.update({"status": "completed", "finished_at": time.time(), "summary": summary})
        self.store.put_run(run)
        self.store.put_trace(run_id, "run.finished", summary)
        return {
            "schema_version": "sentinel.eval.result.v1",
            "run": {k: v for k, v in run.items() if k != "config"},
            "config_fingerprint": resolved.fingerprint,
            "plan": {"cell_count": plan["cell_count"], "assertion_count": plan["assertion_count"]},
            "summary": summary,
            "cells": cell_results,
        }

    def replay(self, run_id: str) -> dict[str, Any]:
        run = self.store.get_run(run_id)
        if not run:
            raise ValueError(f"unknown run: {run_id}")
        return {"schema_version": "sentinel.replay.v1", "run": run, "replayable": True}

    def _prompts(self, config: dict[str, Any]) -> list[dict[str, Any]]:
        prompts = []
        for idx, prompt in enumerate(as_list(config.get("prompts"))):
            if isinstance(prompt, str):
                prompts.append({"id": f"prompt-{idx}", "template": prompt})
            elif isinstance(prompt, dict):
                templates = [prompt.get("template", prompt.get("prompt", ""))]
                templates.extend(prompt.get("permutations", []) or [])
                for pidx, template in enumerate(templates):
                    prompts.append({"id": str(prompt.get("id") or f"prompt-{idx}") + (f"-p{pidx}" if pidx else ""), "template": str(template)})
        return prompts

    def _providers(self, config: dict[str, Any]) -> list[dict[str, Any]]:
        providers = []
        for idx, provider in enumerate(as_list(config.get("providers"))):
            if isinstance(provider, str):
                providers.append({"id": provider, "type": provider, "model": "default"})
            elif isinstance(provider, dict):
                provider_type = str(provider.get("type") or provider.get("id") or "mock")
                providers.append({"id": str(provider.get("id") or provider_type or f"provider-{idx}"), "type": provider_type, **provider})
        return providers or [{"id": "mock", "type": "mock", "model": "deterministic-mock"}]

    def _datasets(self, config: dict[str, Any], base_dir: str | Path) -> list[Dataset]:
        datasets = []
        for dataset in as_list(config.get("datasets")):
            if isinstance(dataset, str):
                datasets.append(load_dataset(Path(base_dir) / dataset))
            elif isinstance(dataset, dict) and dataset.get("path"):
                datasets.append(load_dataset(Path(base_dir) / str(dataset["path"]), key=dataset.get("key")))
            elif isinstance(dataset, dict) and dataset.get("records"):
                datasets.append(inline_dataset(dataset["records"], str(dataset.get("id") or "inline")))
        variables = as_list(config.get("variables"))
        if variables:
            datasets.append(inline_dataset([item if isinstance(item, dict) else {"value": item} for item in variables], "variables"))
        if not datasets:
            datasets.append(inline_dataset([{}], "empty"))
        return datasets
