from __future__ import annotations

import json
from dataclasses import dataclass
from pathlib import Path
from typing import Any

import yaml

from sentinel.platform.config import config_graph, explain_config, lint_config, resolve_config, simulate_config
from sentinel.platform.formats import dump_canonical, stable_sha256


KNOWN_SCHEMAS = {
    "sentinel.config.v1",
    "sentinel.eval.v1",
    "sentinel.dataset.v1",
    "sentinel.assertion.v1",
    "sentinel.provider.v1",
    "sentinel.run.v1",
    "sentinel.trace.v1",
}

REQUIRED_KEYS = {
    "sentinel.eval.v1": ("name", "providers", "prompts", "assertions"),
    "sentinel.dataset.v1": ("name", "records"),
    "sentinel.assertion.v1": ("name", "assertions"),
    "sentinel.provider.v1": ("providers",),
    "sentinel.config.v1": (),
    "sentinel.run.v1": ("id", "status"),
    "sentinel.trace.v1": ("run_id", "events"),
}

SCHEMA_DEFINITIONS = {
    "sentinel.eval.v1": {
        "type": "object",
        "required": ["schema", "name", "providers", "prompts", "assertions"],
        "properties": {
            "schema": {"const": "sentinel.eval.v1"},
            "name": {"type": "string"},
            "description": {"type": "string"},
            "providers": {"type": "array", "items": {"type": ["object", "string"]}},
            "prompts": {"type": "array", "items": {"type": ["object", "string"]}},
            "variables": {"type": "array", "items": {"type": "object"}},
            "datasets": {"type": "array", "items": {"type": ["object", "string"]}},
            "assertions": {"type": "array", "items": {"type": "object"}},
            "profiles": {"type": "object"},
            "environments": {"type": "object"},
        },
        "additionalProperties": True,
    },
    "sentinel.dataset.v1": {
        "type": "object",
        "required": ["schema", "name", "records"],
        "properties": {
            "schema": {"const": "sentinel.dataset.v1"},
            "name": {"type": "string"},
            "records": {"type": "array", "items": {"type": "object"}},
            "transforms": {"type": "array", "items": {"type": "object"}},
            "slices": {"type": "object"},
            "lineage": {"type": "object"},
        },
        "additionalProperties": True,
    },
    "sentinel.assertion.v1": {
        "type": "object",
        "required": ["schema", "name", "assertions"],
        "properties": {
            "schema": {"const": "sentinel.assertion.v1"},
            "name": {"type": "string"},
            "assertions": {"type": "array", "items": {"type": "object"}},
            "templates": {"type": "object"},
        },
        "additionalProperties": True,
    },
}


@dataclass(frozen=True)
class SntlIssue:
    severity: str
    path: str
    message: str


@dataclass(frozen=True)
class SntlDocument:
    source: str
    data: dict[str, Any]
    schema: str | None
    fingerprint: str
    issues: tuple[SntlIssue, ...]

    @property
    def ok(self) -> bool:
        return not any(issue.severity == "error" for issue in self.issues)

    def require(self) -> SntlDocument:
        if not self.ok:
            raise SntlValidationError(self.issues)
        return self

    def canonical_json(self) -> str:
        return dump_canonical(self.data)

    def to_yaml(self) -> str:
        return dumps(self.data)


@dataclass(frozen=True)
class SntlBundle:
    data: dict[str, Any]
    fingerprint: str
    profile: str | None
    environment: str | None
    layers: tuple[dict[str, Any], ...]
    issues: tuple[SntlIssue, ...]

    @property
    def ok(self) -> bool:
        return not any(issue.severity == "error" for issue in self.issues)

    def require(self) -> SntlBundle:
        if not self.ok:
            raise SntlValidationError(self.issues)
        return self

    def explain(self) -> dict[str, Any]:
        return {
            "schema_version": "sentinel.sntl.explain.v1",
            "fingerprint": self.fingerprint,
            "profile": self.profile,
            "environment": self.environment,
            "layers": list(self.layers),
            "effective_keys": sorted(self.data.keys()),
            "issues": [issue.__dict__ for issue in self.issues],
        }

    def simulate(self) -> dict[str, Any]:
        return simulate_config(self.data)


class SntlValidationError(ValueError):
    def __init__(self, issues: tuple[SntlIssue, ...]):
        self.issues = issues
        message = "; ".join(f"{issue.path}: {issue.message}" for issue in issues if issue.severity == "error")
        super().__init__(message or "sntl validation failed")


def loads(text: str, source: str = "<memory>", schema: str | None = None) -> SntlDocument:
    loaded = yaml.safe_load(text)
    if loaded is None:
        loaded = {}
    if not isinstance(loaded, dict):
        issues = (SntlIssue("error", "$", "root must be an object"),)
        return SntlDocument(source, {}, None, stable_sha256({}), issues)
    selected_schema = schema or loaded.get("schema")
    issues = tuple(validate(loaded, selected_schema))
    return SntlDocument(source, loaded, selected_schema, stable_sha256(loaded), issues)


def load(path: str | Path, schema: str | None = None) -> SntlDocument:
    p = Path(path)
    return loads(p.read_text(encoding="utf-8"), str(p), schema)


def dumps(data: dict[str, Any]) -> str:
    return yaml.safe_dump(data, sort_keys=False, allow_unicode=False)


def dump(data: dict[str, Any], path: str | Path) -> Path:
    p = Path(path)
    p.write_text(dumps(data), encoding="utf-8")
    return p


def fingerprint(data: Any) -> str:
    return stable_sha256(data)


def canonical_json(data: Any) -> str:
    return dump_canonical(data)


def validate(data: dict[str, Any], schema: str | None = None) -> list[SntlIssue]:
    issues: list[SntlIssue] = []
    selected_schema = schema or data.get("schema")
    if selected_schema is None:
        issues.append(SntlIssue("error", "schema", "schema is required"))
    elif selected_schema not in KNOWN_SCHEMAS:
        issues.append(SntlIssue("error", "schema", f"unknown schema {selected_schema}"))
    for key in REQUIRED_KEYS.get(str(selected_schema), ()):
        if key not in data or data.get(key) in (None, "", []):
            issues.append(SntlIssue("error", key, f"{key} is required"))
    for issue in lint_config(data):
        issues.append(SntlIssue(str(issue.get("severity", "error")), str(issue.get("path", "$")), str(issue.get("message", "invalid"))))
    issues.extend(_duplicate_id_issues(data, "providers"))
    issues.extend(_duplicate_id_issues(data, "prompts"))
    issues.extend(_duplicate_id_issues(data, "assertions"))
    issues.extend(_duplicate_id_issues(data, "records"))
    return _dedupe_issues(issues)


def resolve(
    paths: list[str | Path],
    profile: str | None = None,
    environment: str | None = None,
    overrides: dict[str, Any] | None = None,
) -> SntlBundle:
    resolved = resolve_config(paths, profile=profile, environment=environment, overrides=overrides)
    issues = tuple(validate(resolved.data, resolved.data.get("schema")))
    layers = tuple(layer.__dict__ for layer in resolved.layers)
    return SntlBundle(resolved.data, resolved.fingerprint, profile, environment, layers, issues)


def explain(paths: list[str | Path], profile: str | None = None, environment: str | None = None) -> dict[str, Any]:
    resolved = resolve_config(paths, profile=profile, environment=environment)
    payload = explain_config(resolved)
    payload["schema_version"] = "sentinel.sntl.explain.v1"
    return payload


def graph(paths: list[str | Path], profile: str | None = None, environment: str | None = None) -> dict[str, Any]:
    resolved = resolve_config(paths, profile=profile, environment=environment)
    payload = config_graph(resolved)
    payload["schema_version"] = "sentinel.sntl.graph.v1"
    return payload


def simulate(data_or_paths: dict[str, Any] | list[str | Path], profile: str | None = None, environment: str | None = None) -> dict[str, Any]:
    if isinstance(data_or_paths, dict):
        return simulate_config(data_or_paths)
    return simulate_config(resolve(data_or_paths, profile=profile, environment=environment).data)


def json_schema(schema: str) -> dict[str, Any]:
    if schema in SCHEMA_DEFINITIONS:
        return {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": f"https://schema.eresus.security/{schema}.schema.json",
            "title": schema,
            **SCHEMA_DEFINITIONS[schema],
        }
    if schema in KNOWN_SCHEMAS:
        return {
            "$schema": "https://json-schema.org/draft/2020-12/schema",
            "$id": f"https://schema.eresus.security/{schema}.schema.json",
            "title": schema,
            "type": "object",
            "required": ["schema"],
            "properties": {"schema": {"const": schema}},
            "additionalProperties": True,
        }
    raise ValueError(f"unknown schema {schema}")


def write_json_schema(schema: str, path: str | Path) -> Path:
    p = Path(path)
    p.write_text(json.dumps(json_schema(schema), indent=2, sort_keys=True) + "\n", encoding="utf-8")
    return p


def _duplicate_id_issues(data: dict[str, Any], key: str) -> list[SntlIssue]:
    value = data.get(key)
    if not isinstance(value, list):
        return []
    seen: dict[str, int] = {}
    issues: list[SntlIssue] = []
    for idx, item in enumerate(value):
        if not isinstance(item, dict):
            continue
        item_id = item.get("id") or item.get("name")
        if not item_id:
            continue
        item_id = str(item_id)
        if item_id in seen:
            issues.append(SntlIssue("error", f"{key}[{idx}].id", f"duplicate id {item_id}"))
        else:
            seen[item_id] = idx
    return issues


def _dedupe_issues(issues: list[SntlIssue]) -> list[SntlIssue]:
    seen: set[tuple[str, str, str]] = set()
    out: list[SntlIssue] = []
    for issue in issues:
        key = (issue.severity, issue.path, issue.message)
        if key not in seen:
            seen.add(key)
            out.append(issue)
    return out


__all__ = [
    "KNOWN_SCHEMAS",
    "SntlBundle",
    "SntlDocument",
    "SntlIssue",
    "SntlValidationError",
    "canonical_json",
    "dump",
    "dumps",
    "explain",
    "fingerprint",
    "graph",
    "json_schema",
    "load",
    "loads",
    "resolve",
    "simulate",
    "validate",
    "write_json_schema",
]
