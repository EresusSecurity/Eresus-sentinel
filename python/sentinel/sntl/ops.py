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


def patch(data: Any, operations: list[dict[str, Any]]) -> Any:
    from sentinel.sntl.path import get_path, set_path

    result = deepcopy(data)
    for op in operations:
        kind = op.get("op")
        path = op.get("path", "")
        if kind == "replace" or kind == "add":
            result = set_path(result, path, deepcopy(op["value"]))
        elif kind == "remove":
            parts = _split_last(path)
            if parts is None:
                result = None
            else:
                parent_path, last = parts
                parent = get_path(result, parent_path) if parent_path else result
                if isinstance(parent, dict):
                    parent = dict(parent)
                    parent.pop(last, None)
                    result = set_path(result, parent_path, parent) if parent_path else parent
                elif isinstance(parent, list) and isinstance(last, int):
                    parent = list(parent)
                    if 0 <= last < len(parent):
                        parent.pop(last)
                    result = set_path(result, parent_path, parent) if parent_path else parent
    return result


def flatten(data: Any, separator: str = ".", prefix: str = "") -> dict[str, Any]:
    out: dict[str, Any] = {}
    if isinstance(data, dict):
        for key, value in data.items():
            full_key = f"{prefix}{separator}{key}" if prefix else key
            if isinstance(value, (dict, list)):
                out.update(flatten(value, separator, full_key))
            else:
                out[full_key] = value
    elif isinstance(data, list):
        for idx, value in enumerate(data):
            full_key = f"{prefix}[{idx}]"
            if isinstance(value, (dict, list)):
                out.update(flatten(value, separator, full_key))
            else:
                out[full_key] = value
    else:
        out[prefix] = data
    return out


def unflatten(data: dict[str, Any], separator: str = ".") -> Any:
    out: Any = {}
    for flat_key, value in data.items():
        parts = _split_flat_key(flat_key, separator)
        node = out
        for i, part in enumerate(parts[:-1]):
            next_part = parts[i + 1]
            if isinstance(part, int):
                while len(node) <= part:
                    node.append(None)
                if node[part] is None:
                    node[part] = [] if isinstance(next_part, int) else {}
                node = node[part]
            else:
                if part not in node:
                    node[part] = [] if isinstance(next_part, int) else {}
                node = node[part]
        last = parts[-1]
        if isinstance(last, int):
            while len(node) <= last:
                node.append(None)
            node[last] = value
        else:
            node[last] = value
    return out


def _split_flat_key(key: str, separator: str) -> list[str | int]:
    parts: list[str | int] = []
    for segment in key.split(separator):
        while "[" in segment:
            bracket = segment.index("[")
            if bracket > 0:
                parts.append(segment[:bracket])
            close = segment.index("]")
            parts.append(int(segment[bracket + 1 : close]))
            segment = segment[close + 1 :]
        if segment:
            parts.append(segment)
    return parts


def select(data: Any, keys: list[str]) -> Any:
    if isinstance(data, dict):
        return {k: deepcopy(data[k]) for k in keys if k in data}
    if isinstance(data, list):
        return [select(item, keys) for item in data]
    return data


def _split_last(path: str) -> tuple[str, str | int] | None:
    if not path or path in {"$", ""}:
        return None
    if path.endswith("]"):
        bracket = path.rindex("[")
        parent = path[:bracket]
        idx = int(path[bracket + 1 : -1])
        return parent, idx
    if "." in path:
        parent, _, key = path.rpartition(".")
        return parent, key
    return "", path
