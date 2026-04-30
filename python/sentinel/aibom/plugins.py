"""BOM plugin system for extending AIBOM with custom scanners and processors."""
from __future__ import annotations

import importlib
import logging
import pkgutil
from collections.abc import Callable
from typing import Any

from sentinel.aibom.scanners.base import BaseAIBOMScanner

logger = logging.getLogger(__name__)


class PluginRegistry:
    """Registry for AIBOM extension plugins."""

    def __init__(self) -> None:
        self._scanners: dict[str, type[BaseAIBOMScanner]] = {}
        self._processors: dict[str, Callable] = {}
        self._hooks: dict[str, list[Callable]] = {}

    def register_scanner(self, name: str, cls: type[BaseAIBOMScanner]) -> None:
        self._scanners[name] = cls
        logger.info("Registered scanner plugin: %s", name)

    def register_processor(self, name: str, fn: Callable) -> None:
        self._processors[name] = fn
        logger.info("Registered processor plugin: %s", name)

    def register_hook(self, event: str, fn: Callable) -> None:
        self._hooks.setdefault(event, []).append(fn)

    def get_scanner(self, name: str) -> type[BaseAIBOMScanner] | None:
        return self._scanners.get(name)

    def get_processor(self, name: str) -> Callable | None:
        return self._processors.get(name)

    def fire_hook(self, event: str, **kwargs: Any) -> list[Any]:
        results = []
        for fn in self._hooks.get(event, []):
            try:
                results.append(fn(**kwargs))
            except Exception as e:
                logger.warning("Hook %s failed: %s", event, e)
        return results

    def create_scanners(self) -> list[BaseAIBOMScanner]:
        return [cls() for cls in self._scanners.values()]

    @property
    def scanner_count(self) -> int:
        return len(self._scanners)

    @property
    def processor_count(self) -> int:
        return len(self._processors)

    def all_scanner_names(self) -> list[str]:
        return sorted(self._scanners.keys())

    def all_processor_names(self) -> list[str]:
        return sorted(self._processors.keys())


_global_registry = PluginRegistry()


def get_global_registry() -> PluginRegistry:
    return _global_registry


def discover_plugins(package_name: str = "sentinel_aibom_plugins") -> int:
    """Auto-discover plugins from a namespace package."""
    count = 0
    try:
        pkg = importlib.import_module(package_name)
    except ImportError:
        return 0

    for _importer, modname, _ispkg in pkgutil.iter_modules(pkg.__path__):
        try:
            mod = importlib.import_module(f"{package_name}.{modname}")
            if hasattr(mod, "register"):
                mod.register(_global_registry)
                count += 1
        except Exception as e:
            logger.warning("Failed to load plugin %s: %s", modname, e)
    return count
