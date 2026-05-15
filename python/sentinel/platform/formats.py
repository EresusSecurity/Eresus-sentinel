from __future__ import annotations

import json
import tomllib
from pathlib import Path
from typing import Any

import yaml


STRUCTURED_SUFFIXES = {".json", ".toml", ".yaml", ".yml", ".sntl", ".sentinel"}


def load_structured(path: str | Path) -> Any:
    p = Path(path)
    text = p.read_text(encoding="utf-8")
    suffix = p.suffix.lower()
    if suffix == ".json":
        return json.loads(text)
    if suffix == ".toml":
        return tomllib.loads(text)
    if suffix in {".yaml", ".yml", ".sntl", ".sentinel"}:
        loaded = yaml.safe_load(text)
        return {} if loaded is None else loaded
    raise ValueError(f"unsupported structured file: {p}")


def dump_canonical(value: Any) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True, default=str)


def stable_sha256(value: Any) -> str:
    import hashlib

    return hashlib.sha256(dump_canonical(value).encode("utf-8")).hexdigest()


def as_list(value: Any) -> list[Any]:
    if value is None:
        return []
    if isinstance(value, list):
        return value
    return [value]
