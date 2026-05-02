"""Scanner plugin SDK primitives."""

from __future__ import annotations

from dataclasses import dataclass, field
from importlib.metadata import entry_points
from pathlib import Path

from sentinel.finding import Finding

PLUGIN_SDK_SCHEMA_VERSION = "sentinel.plugin-sdk.v1"


@dataclass(frozen=True)
class ScannerPluginSpec:
    name: str
    version: str = "0.1.0"
    supported_extensions: tuple[str, ...] = ()
    metadata: dict[str, str] = field(default_factory=dict)


class BaseScannerPlugin:
    spec = ScannerPluginSpec(name="unnamed")

    def scan_path(self, path: str | Path) -> list[Finding]:
        raise NotImplementedError


def discover_scanner_plugins(group: str = "sentinel.scanners") -> list[object]:
    """Load scanner plugin entry points."""
    found = entry_points()
    if hasattr(found, "select"):
        selected = found.select(group=group)
    else:
        selected = found.get(group, [])
    return [entry_point.load() for entry_point in selected]
