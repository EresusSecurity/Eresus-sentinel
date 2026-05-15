from __future__ import annotations

import re
from typing import Any

_TEMPLATE_RE = re.compile(r"\{\{\s*([A-Za-z_][A-Za-z0-9_.]*)\s*\}\}")
_SENTINEL_TEMPLATE_RE = re.compile(r"\$\{\s*([A-Za-z_][A-Za-z0-9_.]*)\s*\}")


def interpolate(template: str, variables: dict[str, Any], strict: bool = False) -> str:
    def _replace(match: re.Match) -> str:
        key = match.group(1)
        value = _deep_get(variables, key)
        if value is None:
            if strict:
                raise KeyError(f"template variable not found: {key!r}")
            return match.group(0)
        return str(value)

    result = _TEMPLATE_RE.sub(_replace, template)
    result = _SENTINEL_TEMPLATE_RE.sub(_replace, result)
    return result


def interpolate_document(data: Any, variables: dict[str, Any], strict: bool = False) -> Any:
    if isinstance(data, str):
        return interpolate(data, variables, strict)
    if isinstance(data, dict):
        return {k: interpolate_document(v, variables, strict) for k, v in data.items()}
    if isinstance(data, list):
        return [interpolate_document(item, variables, strict) for item in data]
    return data


def expand_matrix(variables: list[dict[str, Any]]) -> list[dict[str, Any]]:
    if not variables:
        return [{}]
    return [dict(row) for row in variables]


def cartesian_matrix(dimensions: list[list[dict[str, Any]]]) -> list[dict[str, Any]]:
    if not dimensions:
        return [{}]
    result: list[dict[str, Any]] = [{}]
    for dimension in dimensions:
        new_result: list[dict[str, Any]] = []
        for existing in result:
            for var_set in dimension:
                new_result.append({**existing, **var_set})
        result = new_result
    return result


def render_prompt(template: str, variable_sets: list[dict[str, Any]], strict: bool = False) -> list[str]:
    return [interpolate(template, vs, strict) for vs in variable_sets]


def extract_variables(template: str) -> list[str]:
    seen: set[str] = set()
    result: list[str] = []
    for match in _TEMPLATE_RE.finditer(template):
        key = match.group(1)
        if key not in seen:
            seen.add(key)
            result.append(key)
    for match in _SENTINEL_TEMPLATE_RE.finditer(template):
        key = match.group(1)
        if key not in seen:
            seen.add(key)
            result.append(key)
    return result


def _deep_get(data: dict[str, Any], key: str) -> Any:
    parts = key.split(".")
    current: Any = data
    for part in parts:
        if not isinstance(current, dict) or part not in current:
            return None
        current = current[part]
    return current
