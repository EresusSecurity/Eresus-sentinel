"""
Eresus Sentinel — Plugin Auto-Discovery Engine.

Automatically discovers all
scanner classes from the `firewall/input/`, `firewall/output/`, and `artifact/`
directories. No manual registration required — just implement the base class
and drop your file into the correct directory.


Features:
  - Auto-discover InputScanner subclasses from firewall/input/
  - Auto-discover OutputScanner subclasses from firewall/output/
  - Auto-discover artifact scanners with scan_file() from artifact/
  - Registry caching for O(1) repeated lookups
  - Graceful degradation: if a scanner fails to import, log and skip
  - Metadata extraction: docstrings, supported file types

Usage:
    from sentinel._plugins import get_input_scanners, get_output_scanners

    # Returns {"injection": PromptInjectionScanner, ...}
    input_registry = get_input_scanners()

    # Returns {"sensitive": SensitiveDataScanner, ...}
    output_registry = get_output_scanners()
"""

from __future__ import annotations

import importlib
import inspect
import logging
import pkgutil
from pathlib import Path
from typing import Any

logger = logging.getLogger(__name__)

# ── Cache ─────────────────────────────────────────────────────────

_input_cache: dict[str, type] | None = None
_output_cache: dict[str, type] | None = None
_artifact_cache: dict[str, type] | None = None


# ── Discovery Core ────────────────────────────────────────────────

def _discover_classes(
    package_path: str,
    base_class: type | None = None,
    method_check: str | None = None,
) -> dict[str, type]:
    """
    Discover all classes in a package that inherit from base_class
    or implement a given method.

    Args:
        package_path: Dotted Python package path (e.g., "sentinel.firewall.input").
        base_class: Filter classes that inherit from this.
        method_check: Alternatively, filter classes that implement this method.

    Returns:
        Dict mapping snake_case scanner names to class objects.
    """
    registry: dict[str, type] = {}

    try:
        package = importlib.import_module(package_path)
    except ImportError as e:
        logger.error("Failed to import package %s: %s", package_path, e)
        return registry

    package_dir = Path(package.__file__).parent

    for importer, modname, ispkg in pkgutil.iter_modules([str(package_dir)]):
        if modname.startswith("_"):
            continue

        full_module_name = f"{package_path}.{modname}"
        try:
            module = importlib.import_module(full_module_name)
        except Exception as e:
            logger.warning("Skipping %s: import failed — %s", full_module_name, e)
            continue

        for attr_name, obj in inspect.getmembers(module, inspect.isclass):
            # Skip private classes, base classes, and non-locals
            if attr_name.startswith("_"):
                continue
            if obj.__module__ != full_module_name:
                continue

            # Check inheritance
            if base_class and not issubclass(obj, base_class):
                continue
            if base_class and obj is base_class:
                continue

            # Or check method presence
            if method_check and not hasattr(obj, method_check):
                continue

            # Generate registry key: ClassName → snake_case
            key = _to_registry_key(attr_name)
            if key in registry:
                existing = registry[key]
                logger.warning(
                    "Plugin key collision: %r already registered as %s.%s; "
                    "overwriting with %s.%s — rename one of the classes to avoid this",
                    key,
                    existing.__module__,
                    existing.__name__,
                    full_module_name,
                    attr_name,
                )
            registry[key] = obj
            logger.debug("Discovered: %s → %s.%s", key, full_module_name, attr_name)

    return registry


def _to_registry_key(class_name: str) -> str:
    """
    Convert a class name to a snake_case registry key.

    Examples:
        PromptInjectionScanner → injection
        SensitiveDataScanner → sensitive
        ToxicityScanner → toxicity
        BanSubstringsScanner → ban_substrings
        GibberishOutputScanner → gibberish
    """
    import re

    # Remove common suffixes
    name = class_name
    for suffix in ("Scanner", "OutputScanner", "InputScanner", "Detector", "Validator", "Analyzer"):
        if name.endswith(suffix) and name != suffix:
            name = name[: -len(suffix)]
            break

    # Remove common prefixes
    for prefix in ("Prompt", "Malicious"):
        if name.startswith(prefix) and len(name) > len(prefix):
            name = name[len(prefix):]

    # CamelCase → snake_case
    s = re.sub(r"([A-Z]+)([A-Z][a-z])", r"\1_\2", name)
    s = re.sub(r"([a-z\d])([A-Z])", r"\1_\2", s)
    return s.lower().strip("_")


# ── Public API ────────────────────────────────────────────────────

def get_input_scanners(force_reload: bool = False) -> dict[str, type]:
    """
    Get all input scanner classes auto-discovered from sentinel.firewall.input.

    Returns:
        Dict mapping scanner name → InputScanner subclass.
    """
    global _input_cache
    if _input_cache is not None and not force_reload:
        return _input_cache

    from sentinel.firewall.base import InputScanner
    _input_cache = _discover_classes("sentinel.firewall.input", base_class=InputScanner)
    logger.info("Input scanner registry: %d scanners", len(_input_cache))
    return _input_cache


def get_output_scanners(force_reload: bool = False) -> dict[str, type]:
    """
    Get all output scanner classes auto-discovered from sentinel.firewall.output.

    Returns:
        Dict mapping scanner name → OutputScanner subclass.
    """
    global _output_cache
    if _output_cache is not None and not force_reload:
        return _output_cache

    from sentinel.firewall.base import OutputScanner
    _output_cache = _discover_classes("sentinel.firewall.output", base_class=OutputScanner)
    logger.info("Output scanner registry: %d scanners", len(_output_cache))
    return _output_cache


def get_artifact_scanners(force_reload: bool = False) -> dict[str, type]:
    """
    Get all artifact scanner classes auto-discovered from sentinel.artifact.

    Returns:
        Dict mapping scanner name → class with scan_file() method.
    """
    global _artifact_cache
    if _artifact_cache is not None and not force_reload:
        return _artifact_cache

    _artifact_cache = _discover_classes(
        "sentinel.artifact",
        method_check="scan_file",
    )
    logger.info("Artifact scanner registry: %d scanners", len(_artifact_cache))
    return _artifact_cache


def list_all_plugins() -> dict[str, list[str]]:
    """
    List all discovered plugins grouped by category.

    Returns:
        {"input": [...], "output": [...], "artifact": [...]}
    """
    return {
        "input": sorted(get_input_scanners().keys()),
        "output": sorted(get_output_scanners().keys()),
        "artifact": sorted(get_artifact_scanners().keys()),
    }


def get_plugin_info(category: str, name: str) -> dict[str, Any]:
    """
    Get metadata about a specific plugin.

    Args:
        category: "input", "output", or "artifact".
        name: Registry key name.

    Returns:
        Dict with class name, module, docstring, etc.
    """
    registries = {
        "input": get_input_scanners,
        "output": get_output_scanners,
        "artifact": get_artifact_scanners,
    }

    getter = registries.get(category)
    if not getter:
        return {"error": f"Unknown category: {category}"}

    registry = getter()
    cls = registry.get(name)
    if not cls:
        return {"error": f"Plugin not found: {category}/{name}"}

    return {
        "name": name,
        "class": cls.__name__,
        "module": cls.__module__,
        "docstring": (cls.__doc__ or "").strip().split("\n")[0],
        "category": category,
        "methods": [m for m in dir(cls) if not m.startswith("_") and callable(getattr(cls, m, None))],
    }


def reload_all() -> None:
    """Force reload all plugin registries."""
    global _input_cache, _output_cache, _artifact_cache
    _input_cache = None
    _output_cache = None
    _artifact_cache = None
    get_input_scanners(force_reload=True)
    get_output_scanners(force_reload=True)
    get_artifact_scanners(force_reload=True)
    logger.info("All plugin registries reloaded")
