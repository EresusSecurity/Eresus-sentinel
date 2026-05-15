from __future__ import annotations

from copy import deepcopy
from typing import Any


def merge(left: Any, right: Any) -> Any:
    if isinstance(left, dict) and isinstance(right, dict):
        out = deepcopy(left)
        for key, value in right.items():
            out[key] = merge(out[key], value) if key in out else deepcopy(value)
        return out
    if right is None:
        return deepcopy(left)
    return deepcopy(right)


def diff(left: Any, right: Any, path: str = "$") -> list[dict[str, Any]]:
    if isinstance(left, dict) and isinstance(right, dict):
        out: list[dict[str, Any]] = []
        keys = sorted(set(left) | set(right))
        for key in keys:
            child = f"{path}.{key}" if path != "$" else key
            if key not in left:
                out.append({"op": "add", "path": child, "value": right[key]})
            elif key not in right:
                out.append({"op": "remove", "path": child, "old": left[key]})
            else:
                out.extend(diff(left[key], right[key], child))
        return out
    if isinstance(left, list) and isinstance(right, list):
        out = []
        max_len = max(len(left), len(right))
        for idx in range(max_len):
            child = f"{path}[{idx}]"
            if idx >= len(left):
                out.append({"op": "add", "path": child, "value": right[idx]})
            elif idx >= len(right):
                out.append({"op": "remove", "path": child, "old": left[idx]})
            else:
                out.extend(diff(left[idx], right[idx], child))
        return out
    if left != right:
        return [{"op": "replace", "path": path, "old": left, "value": right}]
    return []


def redact(data: Any, keys: set[str] | None = None, replacement: str = "[redacted]") -> Any:
    sensitive = keys or {"api_key", "apikey", "secret", "token", "password", "private_key", "credential"}
    if isinstance(data, dict):
        out = {}
        for key, value in data.items():
            lowered = str(key).lower()
            out[key] = replacement if any(term in lowered for term in sensitive) else redact(value, sensitive, replacement)
        return out
    if isinstance(data, list):
        return [redact(value, sensitive, replacement) for value in data]
    return data
