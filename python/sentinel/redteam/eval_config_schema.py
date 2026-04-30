"""Eval config schema validation for redteam evaluation runs."""
from __future__ import annotations

import logging
from dataclasses import dataclass, field
from typing import Any

logger = logging.getLogger(__name__)


@dataclass
class EvalProvider:
    name: str
    model: str = ""
    api_key_env: str = ""
    base_url: str = ""
    max_tokens: int = 4096
    temperature: float = 0.0


@dataclass
class EvalDataset:
    name: str
    path: str = ""
    format: str = "jsonl"  # "jsonl", "csv", "json"
    sample_size: int = 0


@dataclass
class EvalConfig:
    id: str
    name: str = ""
    description: str = ""
    providers: list[EvalProvider] = field(default_factory=list)
    datasets: list[EvalDataset] = field(default_factory=list)
    strategies: list[str] = field(default_factory=list)
    assertions: list[dict[str, Any]] = field(default_factory=list)
    max_concurrency: int = 5
    timeout_seconds: int = 60
    metadata: dict[str, Any] = field(default_factory=dict)


_REQUIRED_FIELDS = {"id"}
_OPTIONAL_FIELDS = {
    "name", "description", "providers", "datasets", "strategies",
    "assertions", "max_concurrency", "timeout_seconds", "metadata",
}


def validate_eval_config(data: dict[str, Any]) -> tuple[bool, list[str]]:
    """Validate an eval config dict. Returns (is_valid, errors)."""
    errors: list[str] = []

    for req in _REQUIRED_FIELDS:
        if req not in data:
            errors.append(f"Missing required field: {req}")

    unknown = set(data.keys()) - _REQUIRED_FIELDS - _OPTIONAL_FIELDS
    for key in unknown:
        errors.append(f"Unknown field: {key}")

    providers = data.get("providers", [])
    if not isinstance(providers, list):
        errors.append("'providers' must be a list")
    else:
        for i, p in enumerate(providers):
            if not isinstance(p, dict):
                errors.append(f"providers[{i}] must be a dict")
            elif "name" not in p:
                errors.append(f"providers[{i}] missing 'name'")

    datasets = data.get("datasets", [])
    if not isinstance(datasets, list):
        errors.append("'datasets' must be a list")

    assertions = data.get("assertions", [])
    if not isinstance(assertions, list):
        errors.append("'assertions' must be a list")
    else:
        for i, a in enumerate(assertions):
            if not isinstance(a, dict):
                errors.append(f"assertions[{i}] must be a dict")
            elif "type" not in a:
                errors.append(f"assertions[{i}] missing 'type'")

    timeout = data.get("timeout_seconds")
    if timeout is not None and (not isinstance(timeout, (int, float)) or timeout <= 0):
        errors.append("'timeout_seconds' must be a positive number")

    return (len(errors) == 0, errors)


def parse_eval_config(data: dict[str, Any]) -> EvalConfig:
    """Parse a validated eval config dict into an EvalConfig dataclass."""
    providers = [
        EvalProvider(
            name=p["name"],
            model=p.get("model", ""),
            api_key_env=p.get("api_key_env", ""),
            base_url=p.get("base_url", ""),
            max_tokens=p.get("max_tokens", 4096),
            temperature=p.get("temperature", 0.0),
        )
        for p in data.get("providers", [])
        if isinstance(p, dict) and "name" in p
    ]

    datasets = [
        EvalDataset(
            name=d["name"],
            path=d.get("path", ""),
            format=d.get("format", "jsonl"),
            sample_size=d.get("sample_size", 0),
        )
        for d in data.get("datasets", [])
        if isinstance(d, dict) and "name" in d
    ]

    return EvalConfig(
        id=data["id"],
        name=data.get("name", ""),
        description=data.get("description", ""),
        providers=providers,
        datasets=datasets,
        strategies=data.get("strategies", []),
        assertions=data.get("assertions", []),
        max_concurrency=data.get("max_concurrency", 5),
        timeout_seconds=data.get("timeout_seconds", 60),
        metadata=data.get("metadata", {}),
    )
