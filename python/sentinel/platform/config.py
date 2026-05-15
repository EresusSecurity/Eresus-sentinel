from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path
from typing import Any

from sentinel.platform.formats import as_list, load_structured, stable_sha256


SCHEMAS = {
    "sentinel.config.v1",
    "sentinel.eval.v1",
    "sentinel.dataset.v1",
    "sentinel.assertion.v1",
    "sentinel.provider.v1",
    "sentinel.run.v1",
    "sentinel.trace.v1",
    "sentinel.plugin.v1",
    "sentinel.rulepack.v1",
    "sentinel.redteam.v1",
    "sentinel.runtime.v1",
    "sentinel.policy.v1",
    "sentinel.baseline.v1",
    "sentinel.report.v1",
}


@dataclass(frozen=True)
class ConfigLayer:
    path: str
    fingerprint: str
    keys: list[str]


@dataclass(frozen=True)
class ResolvedConfig:
    data: dict[str, Any]
    layers: list[ConfigLayer]
    profile: str | None
    environment: str | None
    fingerprint: str


def merge_values(left: Any, right: Any) -> Any:
    if isinstance(left, dict) and isinstance(right, dict):
        merged = dict(left)
        for key in sorted(right):
            merged[key] = merge_values(merged.get(key), right[key]) if key in merged else right[key]
        return merged
    if right is None:
        return left
    return right


def _resolve_named_block(blocks: dict[str, Any], name: str, seen: tuple[str, ...] = ()) -> dict[str, Any]:
    if name in seen:
        raise ValueError(f"cyclic inheritance: {' > '.join((*seen, name))}")
    raw = blocks.get(name)
    if raw is None:
        raise ValueError(f"unknown inherited block: {name}")
    if not isinstance(raw, dict):
        raise ValueError(f"inherited block must be object: {name}")
    parents = as_list(raw.get("extends"))
    merged: dict[str, Any] = {}
    for parent in parents:
        merged = merge_values(merged, _resolve_named_block(blocks, str(parent), (*seen, name)))
    own = {k: v for k, v in raw.items() if k != "extends"}
    return merge_values(merged, own)


def resolve_config(
    paths: list[str | Path],
    profile: str | None = None,
    environment: str | None = None,
    overrides: dict[str, Any] | None = None,
) -> ResolvedConfig:
    data: dict[str, Any] = {}
    layers: list[ConfigLayer] = []
    for path in paths:
        loaded = load_structured(path)
        if not isinstance(loaded, dict):
            raise ValueError(f"config root must be object: {path}")
        data = merge_values(data, loaded)
        layers.append(ConfigLayer(str(path), stable_sha256(loaded), sorted(str(k) for k in loaded.keys())))
    env_blocks = data.get("environments") or data.get("env") or {}
    if environment:
        if not isinstance(env_blocks, dict):
            raise ValueError("environment blocks must be objects")
        data = merge_values(data, _resolve_named_block(env_blocks, environment))
    profile_blocks = data.get("profiles") or {}
    if profile:
        if not isinstance(profile_blocks, dict):
            raise ValueError("profile blocks must be objects")
        data = merge_values(data, _resolve_named_block(profile_blocks, profile))
    if overrides:
        data = merge_values(data, overrides)
    material = {k: v for k, v in data.items() if k not in {"profiles", "environments", "env"}}
    return ResolvedConfig(material, layers, profile, environment, stable_sha256(material))


def lint_config(config: dict[str, Any]) -> list[dict[str, Any]]:
    issues: list[dict[str, Any]] = []
    schema = config.get("schema")
    if schema and schema not in SCHEMAS:
        issues.append({"severity": "error", "path": "schema", "message": f"unknown schema {schema}"})
    if config.get("schema") == "sentinel.eval.v1" or any(k in config for k in ("prompts", "providers", "assertions")):
        for key in ("prompts", "providers", "assertions"):
            if not as_list(config.get(key)):
                issues.append({"severity": "error", "path": key, "message": f"{key} must not be empty"})
    for idx, provider in enumerate(as_list(config.get("providers"))):
        if isinstance(provider, str):
            continue
        if not isinstance(provider, dict) or not provider.get("id", provider.get("type")):
            issues.append({"severity": "error", "path": f"providers[{idx}]", "message": "provider needs id or type"})
    for idx, prompt in enumerate(as_list(config.get("prompts"))):
        if isinstance(prompt, str):
            continue
        if not isinstance(prompt, dict) or not prompt.get("template", prompt.get("prompt")):
            issues.append({"severity": "error", "path": f"prompts[{idx}]", "message": "prompt needs template"})
    return issues


def explain_config(resolved: ResolvedConfig) -> dict[str, Any]:
    return {
        "schema_version": "sentinel.config.explain.v1",
        "fingerprint": resolved.fingerprint,
        "profile": resolved.profile,
        "environment": resolved.environment,
        "layers": [layer.__dict__ for layer in resolved.layers],
        "effective_keys": sorted(resolved.data.keys()),
        "issues": lint_config(resolved.data),
    }


def config_graph(resolved: ResolvedConfig) -> dict[str, Any]:
    nodes = [{"id": "effective", "type": "config", "label": "effective"}]
    edges: list[dict[str, str]] = []
    for idx, layer in enumerate(resolved.layers):
        node_id = f"layer:{idx}"
        nodes.append({"id": node_id, "type": "layer", "label": layer.path, "fingerprint": layer.fingerprint})
        edges.append({"from": node_id, "to": "effective", "type": "merge"})
    if resolved.environment:
        nodes.append({"id": f"environment:{resolved.environment}", "type": "environment", "label": resolved.environment})
        edges.append({"from": f"environment:{resolved.environment}", "to": "effective", "type": "inherit"})
    if resolved.profile:
        nodes.append({"id": f"profile:{resolved.profile}", "type": "profile", "label": resolved.profile})
        edges.append({"from": f"profile:{resolved.profile}", "to": "effective", "type": "inherit"})
    return {"schema_version": "sentinel.config.graph.v1", "nodes": nodes, "edges": edges}


def simulate_config(config: dict[str, Any]) -> dict[str, Any]:
    prompts = len(as_list(config.get("prompts")))
    providers = len(as_list(config.get("providers")))
    assertions = len(as_list(config.get("assertions")))
    datasets = len(as_list(config.get("datasets"))) or (1 if as_list(config.get("variables")) else 0)
    variables = len(as_list(config.get("variables"))) or 1
    cells = max(prompts, 1) * max(providers, 1) * max(datasets, 1) * max(variables, 1)
    return {
        "schema_version": "sentinel.config.simulation.v1",
        "matrix": {
            "prompts": prompts,
            "providers": providers,
            "assertions_per_cell": assertions,
            "datasets": datasets,
            "variables": variables,
            "cells": cells,
        },
        "deterministic": True,
        "requires_llm": False,
    }
