"""
Eresus Sentinel — Data Loader.

Central utility for loading YAML pattern databases. All firewall scanners
load their patterns from YAML files in the `data/` directory instead of
hardcoding them in Python modules.

Features:
  - Lazy loading with caching (patterns loaded once, reused forever)
  - Custom data path override via SENTINEL_DATA_DIR env var
  - Schema validation on load
  - Hot-reload support for dev mode
"""

from __future__ import annotations

import logging
import os
import re
from functools import lru_cache
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# Default data directory: sentinel/data/
_DEFAULT_DATA_DIR = Path(__file__).parent / "data"

# Override with env var
_DATA_DIR = Path(os.environ.get("SENTINEL_DATA_DIR", str(_DEFAULT_DATA_DIR)))


def _load_yaml(filename: str) -> dict:
    """Load and parse a YAML file from the data directory."""
    import yaml

    filepath = _DATA_DIR / filename
    if not filepath.exists():
        logger.warning("Data file not found: %s, using empty config", filepath)
        return {}

    with open(filepath, "r", encoding="utf-8") as f:
        data = yaml.safe_load(f)

    logger.debug("Loaded data file: %s (%d bytes)", filepath, filepath.stat().st_size)
    return data or {}


@lru_cache(maxsize=32)
def load_data(filename: str) -> dict:
    """
    Load a YAML data file with caching.

    Args:
        filename: Name of the YAML file (e.g., 'toxicity.yaml').

    Returns:
        Parsed YAML dictionary.
    """
    return _load_yaml(filename)


def compile_patterns(
    raw_patterns: list[dict],
    regex_key: str = "regex",
    flags: int = re.IGNORECASE,
) -> list[tuple[re.Pattern, dict]]:
    """
    Compile a list of pattern dicts from YAML into (compiled_regex, metadata) tuples.

    Each dict should have a regex_key field plus optional metadata fields.

    Args:
        raw_patterns: List of dicts from YAML, each with at least a regex field.
        regex_key: Key name for the regex string in each dict.
        flags: Regex compilation flags.

    Returns:
        List of (compiled_pattern, metadata_dict) tuples.
    """
    compiled = []
    for entry in raw_patterns:
        pattern_str = entry.get(regex_key, "")
        if not pattern_str:
            continue
        try:
            pattern = re.compile(pattern_str, flags)
            meta = {k: v for k, v in entry.items() if k != regex_key}
            compiled.append((pattern, meta))
        except re.error as e:
            logger.warning("Invalid regex in data file: %s → %s", pattern_str[:60], e)
    return compiled


def compile_pattern_list(
    raw_patterns: list[str],
    flags: int = re.IGNORECASE,
) -> list[re.Pattern]:
    """
    Compile a simple list of regex strings into compiled patterns.

    Args:
        raw_patterns: List of regex strings.
        flags: Regex compilation flags.

    Returns:
        List of compiled re.Pattern objects.
    """
    compiled = []
    for p in raw_patterns:
        try:
            compiled.append(re.compile(p, flags))
        except re.error as e:
            logger.warning("Invalid regex: %s → %s", p[:60], e)
    return compiled


def get_data_dir() -> Path:
    """Return the current data directory path."""
    return _DATA_DIR


def reload_data(filename: str) -> dict:
    """Force reload a data file (bypasses cache)."""
    load_data.cache_clear()
    return load_data(filename)


def validate_schema(data: dict, required_keys: list[str]) -> list[str]:
    """
    Validate a loaded data file against expected schema.

    Args:
        data: Parsed YAML dictionary.
        required_keys: Keys that must exist at root level.

    Returns:
        List of validation error strings (empty = valid).
    """
    errors = []
    for key in required_keys:
        if key not in data:
            errors.append(f"Missing required key: '{key}'")
    return errors


def load_and_validate(filename: str, required_keys: list[str]) -> tuple[dict, list[str]]:
    """
    Load a YAML file and validate its schema.

    Returns:
        Tuple of (data, errors). If errors is non-empty, data may be incomplete.
    """
    data = load_data(filename)
    errors = validate_schema(data, required_keys)
    if errors:
        logger.warning("Schema validation failed for %s: %s", filename, errors)
    return data, errors


def load_batch(filenames: list[str]) -> dict[str, dict]:
    """
    Load multiple data files at once.

    Returns:
        Dict mapping filename to parsed data.
    """
    return {f: load_data(f) for f in filenames}


def file_integrity(filename: str) -> dict:
    """
    Return integrity metadata for a data file (SHA256, size, mtime).

    Useful for verifying that pattern databases haven't been tampered with.
    """
    import hashlib

    filepath = _DATA_DIR / filename
    if not filepath.exists():
        return {"exists": False, "filename": filename}

    stat = filepath.stat()
    sha256 = hashlib.sha256(filepath.read_bytes()).hexdigest()

    return {
        "exists": True,
        "filename": filename,
        "path": str(filepath),
        "size_bytes": stat.st_size,
        "sha256": sha256,
        "mtime": stat.st_mtime,
    }


def pattern_stats() -> dict:
    """
    Return statistics about all loaded pattern data files.

    Useful for debugging and verifying scanner data quality.
    """
    stats = {}
    if not _DATA_DIR.exists():
        return {"error": f"Data directory not found: {_DATA_DIR}"}

    for filepath in sorted(_DATA_DIR.glob("*.yaml")):
        try:
            data = load_data(filepath.name)
            # Count patterns at various depths
            pattern_count = 0
            for key, value in data.items():
                if isinstance(value, list):
                    pattern_count += len(value)
                elif isinstance(value, dict):
                    for sub_val in value.values():
                        if isinstance(sub_val, list):
                            pattern_count += len(sub_val)

            stats[filepath.name] = {
                "keys": list(data.keys()),
                "pattern_count": pattern_count,
                "size_bytes": filepath.stat().st_size,
            }
        except Exception as e:
            stats[filepath.name] = {"error": str(e)}

    return stats


def list_data_files() -> list[str]:
    """List all available YAML data files."""
    if not _DATA_DIR.exists():
        return []
    return sorted(f.name for f in _DATA_DIR.glob("*.yaml"))

