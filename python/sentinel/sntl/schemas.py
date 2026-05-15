from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from sentinel.sntl.types import SntlIssue


KNOWN_SCHEMAS = {
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

REQUIRED_KEYS = {
    "sentinel.eval.v1": ("name", "providers", "prompts", "assertions"),
    "sentinel.dataset.v1": ("name", "records"),
    "sentinel.assertion.v1": ("name", "assertions"),
    "sentinel.provider.v1": ("providers",),
    "sentinel.config.v1": (),
    "sentinel.run.v1": ("id", "status"),
    "sentinel.trace.v1": ("run_id", "events"),
    "sentinel.plugin.v1": ("id", "name", "version", "kind"),
    "sentinel.rulepack.v1": ("name", "rules"),
    "sentinel.redteam.v1": ("name", "attacks"),
    "sentinel.runtime.v1": ("name", "policies"),
    "sentinel.policy.v1": ("name", "rules"),
    "sentinel.baseline.v1": ("name", "runs"),
    "sentinel.report.v1": ("run_id", "artifacts"),
}

SCHEMA_DEFINITIONS: dict[str, dict] = {
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
    "sentinel.plugin.v1": {
        "type": "object",
        "required": ["schema", "id", "name", "version", "kind"],
        "properties": {
            "schema": {"const": "sentinel.plugin.v1"},
            "id": {"type": "string"},
            "name": {"type": "string"},
            "version": {"type": "string"},
            "kind": {"type": "string"},
            "permissions": {"type": "array"},
            "hooks": {"type": "array"},
        },
        "additionalProperties": True,
    },
    "sentinel.redteam.v1": {
        "type": "object",
        "required": ["schema", "name", "attacks"],
        "properties": {
            "schema": {"const": "sentinel.redteam.v1"},
            "name": {"type": "string"},
            "description": {"type": "string"},
            "attacks": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["id"],
                    "properties": {
                        "id": {"type": "string"},
                        "pack": {"type": "string"},
                        "goal": {"type": "string"},
                        "assertions": {"type": "array"},
                        "repeat": {"type": "integer", "minimum": 1},
                        "tags": {"type": "array", "items": {"type": "string"}},
                    },
                },
            },
            "scoring": {
                "type": "object",
                "properties": {
                    "method": {"type": "string", "enum": ["deterministic", "model", "hybrid"]},
                    "fail_on": {"type": "string", "enum": ["critical", "high", "medium", "low"]},
                    "pass_threshold": {"type": "number", "minimum": 0.0, "maximum": 1.0},
                },
            },
            "providers": {"type": "array"},
            "environments": {"type": "object"},
        },
        "additionalProperties": True,
    },
    "sentinel.runtime.v1": {
        "type": "object",
        "required": ["schema", "name", "policies"],
        "properties": {
            "schema": {"const": "sentinel.runtime.v1"},
            "name": {"type": "string"},
            "description": {"type": "string"},
            "policies": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["id", "action"],
                    "properties": {
                        "id": {"type": "string"},
                        "action": {"type": "string", "enum": ["block", "allow", "flag", "redact", "log"]},
                        "enabled": {"type": "boolean"},
                        "conditions": {"type": "array"},
                        "priority": {"type": "integer"},
                        "tags": {"type": "array", "items": {"type": "string"}},
                    },
                },
            },
            "default_action": {"type": "string", "enum": ["block", "allow", "flag"]},
            "cache": {"type": "object"},
            "environments": {"type": "object"},
        },
        "additionalProperties": True,
    },
    "sentinel.rulepack.v1": {
        "type": "object",
        "required": ["schema", "name", "rules"],
        "properties": {
            "schema": {"const": "sentinel.rulepack.v1"},
            "name": {"type": "string"},
            "description": {"type": "string"},
            "version": {"type": "string"},
            "rules": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["id"],
                    "properties": {
                        "id": {"type": "string"},
                        "severity": {"type": "string", "enum": ["critical", "high", "medium", "low", "info"]},
                        "enabled": {"type": "boolean"},
                        "pattern": {"type": "string"},
                        "tags": {"type": "array", "items": {"type": "string"}},
                        "description": {"type": "string"},
                    },
                },
            },
            "extends": {"type": ["string", "array"]},
            "tags": {"type": "array", "items": {"type": "string"}},
        },
        "additionalProperties": True,
    },
    "sentinel.policy.v1": {
        "type": "object",
        "required": ["schema", "name", "rules"],
        "properties": {
            "schema": {"const": "sentinel.policy.v1"},
            "name": {"type": "string"},
            "description": {"type": "string"},
            "rules": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["id", "action"],
                    "properties": {
                        "id": {"type": "string"},
                        "action": {"type": "string"},
                        "match": {"type": "object"},
                        "severity": {"type": "string"},
                        "enabled": {"type": "boolean"},
                    },
                },
            },
            "extends": {"type": ["string", "array"]},
            "environments": {"type": "object"},
        },
        "additionalProperties": True,
    },
    "sentinel.provider.v1": {
        "type": "object",
        "required": ["schema", "providers"],
        "properties": {
            "schema": {"const": "sentinel.provider.v1"},
            "providers": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["id"],
                    "properties": {
                        "id": {"type": "string"},
                        "type": {"type": "string"},
                        "model": {"type": "string"},
                        "base_url": {"type": "string"},
                        "timeout": {"type": "integer", "minimum": 0},
                        "max_tokens": {"type": "integer", "minimum": 1},
                        "temperature": {"type": "number", "minimum": 0.0, "maximum": 2.0},
                        "capabilities": {"type": "object"},
                    },
                },
            },
        },
        "additionalProperties": True,
    },
    "sentinel.report.v1": {
        "type": "object",
        "required": ["schema", "run_id", "artifacts"],
        "properties": {
            "schema": {"const": "sentinel.report.v1"},
            "run_id": {"type": "string"},
            "created_at": {"type": "string"},
            "artifacts": {
                "type": "array",
                "items": {
                    "type": "object",
                    "required": ["format", "path"],
                    "properties": {
                        "format": {"type": "string", "enum": ["json", "sarif", "html", "markdown", "csv", "junit"]},
                        "path": {"type": "string"},
                        "size_bytes": {"type": "integer"},
                    },
                },
            },
            "summary": {"type": "object"},
        },
        "additionalProperties": True,
    },
}


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
    issues.extend(_validate_eval_shape(data, str(selected_schema)))
    for key in ("providers", "prompts", "assertions", "records", "rules", "attacks", "policies", "hooks"):
        issues.extend(_duplicate_id_issues(data, key))
    return _dedupe_issues(issues)


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


def _validate_eval_shape(data: dict[str, Any], selected_schema: str) -> list[SntlIssue]:
    issues: list[SntlIssue] = []
    if selected_schema == "sentinel.eval.v1":
        for key in ("prompts", "providers", "assertions"):
            value = data.get(key)
            if not value:
                issues.append(SntlIssue("error", key, f"{key} must not be empty"))
        for idx, provider in enumerate(_as_list(data.get("providers"))):
            if isinstance(provider, str):
                continue
            if not isinstance(provider, dict) or not provider.get("id", provider.get("type")):
                issues.append(SntlIssue("error", f"providers[{idx}]", "provider needs id or type"))
        for idx, prompt in enumerate(_as_list(data.get("prompts"))):
            if isinstance(prompt, str):
                continue
            if not isinstance(prompt, dict) or not prompt.get("template", prompt.get("prompt")):
                issues.append(SntlIssue("error", f"prompts[{idx}]", "prompt needs template"))
    return issues


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


def _as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]
