"""Parse framework-specific configuration files for AI/ML settings."""
from __future__ import annotations

import json
import logging
from pathlib import Path
from typing import Any

import yaml

logger = logging.getLogger(__name__)

_FRAMEWORK_CONFIG_FILES = {
    "langchain.yaml": "langchain",
    "langchain.yml": "langchain",
    "crewai.yaml": "crewai",
    "crewai.yml": "crewai",
    ".langsmith": "langsmith",
    "config.yaml": None,
    "sentinel.toml": "sentinel",
    "mlflow.yaml": "mlflow",
    "wandb/settings": "wandb",
    "dvc.yaml": "dvc",
}


def parse_framework_config(path: Path) -> dict[str, Any]:
    """Parse a framework config file and extract AI-relevant settings."""
    suffix = path.suffix.lower()
    try:
        if suffix in (".yaml", ".yml"):
            return _parse_yaml(path)
        elif suffix == ".json":
            return _parse_json(path)
        elif suffix == ".toml":
            return _parse_toml(path)
        else:
            return {}
    except Exception as e:
        logger.debug("Failed to parse config %s: %s", path, e)
        return {}


def detect_framework(path: Path) -> str | None:
    """Detect the framework from a config file path."""
    name = path.name
    return _FRAMEWORK_CONFIG_FILES.get(name)


def extract_model_refs(config: dict[str, Any]) -> list[dict[str, str]]:
    """Extract model references from parsed config."""
    refs: list[dict[str, str]] = []
    _walk_for_models(config, "", refs)
    return refs


def _walk_for_models(obj: Any, path: str, refs: list[dict[str, str]]) -> None:
    model_keys = {"model", "model_name", "model_id", "llm_model", "deployment_name"}
    if isinstance(obj, dict):
        for k, v in obj.items():
            sub = f"{path}.{k}" if path else k
            if isinstance(v, str) and k.lower() in model_keys and v.strip():
                refs.append({"key": sub, "model": v.strip()})
            _walk_for_models(v, sub, refs)
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            _walk_for_models(item, f"{path}[{i}]", refs)


def _parse_yaml(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    data = yaml.safe_load(text)
    return data if isinstance(data, dict) else {}


def _parse_json(path: Path) -> dict[str, Any]:
    text = path.read_text(encoding="utf-8", errors="replace")
    data = json.loads(text)
    return data if isinstance(data, dict) else {}


def _parse_toml(path: Path) -> dict[str, Any]:
    try:
        import tomllib
    except ImportError:
        try:
            import tomli as tomllib  # type: ignore[no-redef]
        except ImportError:
            return {}
    text = path.read_bytes()
    return tomllib.loads(text.decode("utf-8"))
