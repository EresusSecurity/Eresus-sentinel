from __future__ import annotations

from copy import deepcopy
from typing import Any, Iterable


def query(data: Any, path: str, default: Any = None) -> Any:
    current = data
    for part in _parts(path):
        if isinstance(current, dict) and isinstance(part, str):
            if part not in current:
                return default
            current = current[part]
        elif isinstance(current, list) and isinstance(part, int):
            if part < 0 or part >= len(current):
                return default
            current = current[part]
        else:
            return default
    return current


def get_path(data: Any, path: str, default: Any = None) -> Any:
    return query(data, path, default)


def set_path(data: Any, path: str, value: Any) -> Any:
    out = deepcopy(data)
    current = out
    parts = _parts(path)
    if not parts:
        return value
    for part in parts[:-1]:
        if isinstance(part, int):
            current = current[part]
        else:
            current = current.setdefault(part, {})
    last = parts[-1]
    if isinstance(last, int):
        current[last] = value
    else:
        current[last] = value
    return out


def walk(data: Any, prefix: str = "$") -> Iterable[tuple[str, Any]]:
    yield prefix, data
    if isinstance(data, dict):
        for key, value in data.items():
            yield from walk(value, f"{prefix}.{key}" if prefix != "$" else str(key))
    elif isinstance(data, list):
        for idx, value in enumerate(data):
            yield from walk(value, f"{prefix}[{idx}]")


def wildcard_query(data: Any, path: str) -> list[Any]:
    if path.startswith("$**."):
        field = path[4:]
        return _recursive_field(data, field)
    if path.startswith("**."):
        field = path[3:]
        return _recursive_field(data, field)
    if "[*]" in path:
        return _wildcard_index(data, path)
    return [query(data, path)]


def _recursive_field(data: Any, field: str) -> list[Any]:
    results: list[Any] = []
    if isinstance(data, dict):
        if field in data:
            results.append(data[field])
        for value in data.values():
            results.extend(_recursive_field(value, field))
    elif isinstance(data, list):
        for item in data:
            results.extend(_recursive_field(item, field))
    return results


def _wildcard_index(data: Any, path: str) -> list[Any]:
    star_pos = path.index("[*]")
    prefix = path[:star_pos]
    suffix = path[star_pos + 3:]
    collection = query(data, prefix) if prefix and prefix != "$" else data
    if not isinstance(collection, list):
        return []
    results: list[Any] = []
    for idx in range(len(collection)):
        sub_path = f"[{idx}]{suffix}"
        results.append(query(collection, sub_path))
    return results


def _parts(path: str) -> list[str | int]:
    if path in {"", "$"}:
        return []
    text = path[2:] if path.startswith("$.") else path[1:] if path.startswith("$") else path
    out: list[str | int] = []
    buf = ""
    idx = 0
    while idx < len(text):
        ch = text[idx]
        if ch == ".":
            if buf:
                out.append(buf)
                buf = ""
            idx += 1
        elif ch == "[":
            if buf:
                out.append(buf)
                buf = ""
            end = text.index("]", idx)
            out.append(int(text[idx + 1 : end]))
            idx = end + 1
        else:
            buf += ch
            idx += 1
    if buf:
        out.append(buf)
    return out
